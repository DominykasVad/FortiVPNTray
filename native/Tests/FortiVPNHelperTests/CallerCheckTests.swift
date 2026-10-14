import Testing
import Foundation
import FortiVPNShared
@testable import FortiVPNHelper

/// The real delegate and service over an anonymous XPC listener inside the test
/// process. The peer is the test runner itself: right UID, no signing certificate.
/// A caller signed with the pinned certificate being *accepted* cannot be shown
/// here; spike S1 showed it against a launchd Mach service.
struct CallerCheckTests {
    private struct Version: Equatable, Sendable { let helper: String; let proto: Int; let mode: String }
    private enum Outcome<Value: Sendable>: Sendable { case answered(Value), refused, timedOut }

    /// Resumes a continuation exactly once, whichever of reply, error or timeout comes first.
    private final class Once<Value: Sendable>: @unchecked Sendable {
        // @unchecked Sendable: `continuation` is only touched while holding `lock`.
        private let lock = NSLock()
        private var continuation: CheckedContinuation<Outcome<Value>, Never>?
        init(_ continuation: CheckedContinuation<Outcome<Value>, Never>) { self.continuation = continuation }
        func finish(_ outcome: Outcome<Value>) {
            lock.lock()
            let pending = continuation
            continuation = nil
            lock.unlock()
            pending?.resume(returning: outcome)
        }
    }

    /// Makes one call through a real XPC connection to the real delegate and service.
    /// Waits with a continuation, not a semaphore: a blocked test thread belongs to
    /// Swift's small task pool, and with every one of them blocked the queues XPC
    /// delivers on are starved on a runner with few cores.
    private func call<Value: Sendable>(
        _ arguments: HelperLaunchArguments, clientIdentifier: String = AppIdentity.identifier,
        sessions: SessionController = SessionController(launcher: UnavailableLauncher()),
        _ body: @escaping @Sendable (HelperXPCProtocol, @escaping @Sendable (Value) -> Void) -> Void
    ) async throws -> Value? {
        let check = try #require(CallerCheck(arguments: arguments, sessions: sessions, clientIdentifier: clientIdentifier))
        let listener = NSXPCListener.anonymous()
        listener.delegate = check
        listener.resume()
        defer { listener.invalidate() }
        let connection = NSXPCConnection(listenerEndpoint: listener.endpoint)
        connection.remoteObjectInterface = NSXPCInterface(with: HelperXPCProtocol.self)
        connection.resume()
        defer { connection.invalidate() }
        let outcome = await withCheckedContinuation { (continuation: CheckedContinuation<Outcome<Value>, Never>) in
            let once = Once(continuation)
            guard let proxy = connection.remoteObjectProxyWithErrorHandler({ @Sendable _ in once.finish(.refused) }) as? HelperXPCProtocol else {
                once.finish(.refused)
                return
            }
            body(proxy) { once.finish(.answered($0)) }
            // A dedicated thread, so the timeout fires even if the dispatch pools are busy.
            Thread.detachNewThread {
                Thread.sleep(forTimeInterval: 10)
                once.finish(.timedOut)
            }
        }
        switch outcome {
        case .answered(let value): return value
        case .refused: return nil
        case .timedOut:
            Issue.record("neither an answer nor an error within 10 seconds")
            return nil
        }
    }

    private func ask(_ arguments: HelperLaunchArguments, clientIdentifier: String = AppIdentity.identifier) async throws -> Version? {
        try await call(arguments, clientIdentifier: clientIdentifier) { proxy, done in
            proxy.version { helper, proto, mode in done(Version(helper: helper, proto: proto, mode: mode)) }
        }
    }

    @Test func testUIDOnlyAcceptsTheAllowedUser() async throws {
        let version = try await ask(try HelperLaunchArguments(allowedUID: getuid(), callerCheck: .uidOnly))
        #expect(version == Version(helper: HelperTransport.helperVersion, proto: HelperTransport.protocolVersion, mode: "uid-only"))
    }

    @Test func testAnotherUserIsRefused() async throws {
        #expect(try await ask(try HelperLaunchArguments(allowedUID: getuid() + 1, callerCheck: .uidOnly)) == nil)
    }

    @Test func testSignedModeRefusesACallerWithoutThePinnedCertificate() async throws {
        // The test runner is not signed with this (or any) certificate.
        let pinned = try HelperLaunchArguments(allowedUID: getuid(), callerCheck: .signed(leafSHA1: String(repeating: "0", count: 40)))
        #expect(try await ask(pinned) == nil)
        // The UID check still applies in signed mode.
        let wrongUser = try HelperLaunchArguments(allowedUID: getuid() + 1, callerCheck: .signed(leafSHA1: String(repeating: "0", count: 40)))
        #expect(try await ask(wrongUser) == nil)
    }

    @Test func testUnbuildableRequirementDoesNotFallBackToUIDOnly() throws {
        let signed = try HelperLaunchArguments(allowedUID: getuid(), callerCheck: .signed(leafSHA1: String(repeating: "A", count: 40)))
        let sessions = SessionController(launcher: UnavailableLauncher())
        #expect(CallerCheck(arguments: signed, sessions: sessions, clientIdentifier: "bad\" or anchor apple") == nil)
        #expect(CallerCheck(arguments: signed, sessions: sessions, clientIdentifier: "") == nil)
    }

    // The tunnel calls over the same connection: arguments and replies survive XPC,
    // and the helper validates what arrives rather than trusting the caller.

    private struct Reply: Equatable, Sendable { let value: String?; let error: String? }

    @Test func testConnectOverXPCValidatesTheRequest() async throws {
        let arguments = try HelperLaunchArguments(allowedUID: getuid(), callerCheck: .uidOnly)
        let hostile = Data(#"{"host":"-c/tmp/x","port":443,"auth":{"method":"saml","listenPort":8020},"trustedCerts":[],"useSystemDNSFallback":true}"#.utf8)
        let refused = try await call(arguments) { proxy, done in proxy.connect(hostile) { done(Reply(value: $0, error: $1)) } }
        #expect(refused == Reply(value: nil, error: ConnectRequest.Rejection.host.description))
        let garbage = try await call(arguments) { proxy, done in proxy.connect(Data("x".utf8)) { done(Reply(value: $0, error: $1)) } }
        #expect(garbage == Reply(value: nil, error: ConnectRequest.Rejection.malformed.description))
    }

    @Test func testConnectStatusAndLogOverXPC() async throws {
        let arguments = try HelperLaunchArguments(allowedUID: getuid(), callerCheck: .uidOnly)
        let sessions = SessionController(launcher: AcceptingLauncher())
        let request = try ConnectRequest(host: "vpn.example.com", port: 443).json()
        let connected = try #require(try await call(arguments, sessions: sessions) { proxy, done in
            proxy.connect(request) { done(Reply(value: $0, error: $1)) }
        })
        let id = try #require(connected.value)
        #expect(connected.error == nil)
        // A second connection shares the one session.
        let second = try await call(arguments, sessions: sessions) { proxy, done in proxy.connect(request) { done(Reply(value: $0, error: $1)) } }
        #expect(second == Reply(value: nil, error: "A session is already active."))
        let status = try #require(try await call(arguments, sessions: sessions) { proxy, done in proxy.status { done($0) } })
        #expect(try HelperWire.decode(HelperStatus.self, from: status).sessionID == id)
        let log = try #require(try await call(arguments, sessions: sessions) { proxy, done in
            proxy.readLog(sessionID: id, offset: 0) { done(Reply(value: $0.map { String(decoding: $0, as: UTF8.self) }, error: $1)) }
        })
        #expect(try HelperWire.decode(LogChunk.self, from: Data(try #require(log.value).utf8)) == LogChunk(lines: [], nextOffset: 0))
        let unknown = try await call(arguments, sessions: sessions) { proxy, done in
            proxy.readLog(sessionID: "other", offset: 0) { done(Reply(value: $0.map { String(decoding: $0, as: UTF8.self) }, error: $1)) }
        }
        #expect(unknown == Reply(value: nil, error: "Unknown session."))
        let url = try await call(arguments, sessions: sessions) { proxy, done in proxy.pendingSAMLURL { done(Reply(value: $0, error: nil)) } }
        #expect(url == Reply(value: nil, error: nil))
        let disconnected = try await call(arguments, sessions: sessions) { proxy, done in proxy.disconnect { done(Reply(value: nil, error: $0)) } }
        #expect(disconnected == Reply(value: nil, error: nil))
        #expect(sessions.status() == HelperStatus())
    }

    @Test func testRefusedCallerCannotConnect() async throws {
        let sessions = SessionController(launcher: AcceptingLauncher())
        let arguments = try HelperLaunchArguments(allowedUID: getuid() + 1, callerCheck: .uidOnly)
        let request = try ConnectRequest(host: "vpn.example.com", port: 443).json()
        let reply = try await call(arguments, sessions: sessions) { proxy, done in proxy.connect(request) { done(Reply(value: $0, error: $1)) } }
        #expect(reply == nil)
        #expect(sessions.status() == HelperStatus())
    }

    private struct AcceptingLauncher: TunnelLauncher {
        func start(_ request: ConnectRequest, sessionID: String) throws {}
        func stop() {}
    }
}
