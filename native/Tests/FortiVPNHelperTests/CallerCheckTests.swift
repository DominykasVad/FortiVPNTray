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
    private enum Outcome: Equatable, Sendable { case answered(Version), refused, timedOut }

    /// Resumes a continuation exactly once, whichever of reply, error or timeout comes first.
    private final class Once: @unchecked Sendable {
        // @unchecked Sendable: `continuation` is only touched while holding `lock`.
        private let lock = NSLock()
        private var continuation: CheckedContinuation<Outcome, Never>?
        init(_ continuation: CheckedContinuation<Outcome, Never>) { self.continuation = continuation }
        func finish(_ outcome: Outcome) {
            lock.lock()
            let pending = continuation
            continuation = nil
            lock.unlock()
            pending?.resume(returning: outcome)
        }
    }

    /// Waits with a continuation, not a semaphore: a blocked test thread belongs to
    /// Swift's small task pool, and with every one of them blocked the queues XPC
    /// delivers on are starved on a runner with few cores.
    private func ask(_ arguments: HelperLaunchArguments, clientIdentifier: String = AppIdentity.identifier) async throws -> Version? {
        let check = try #require(CallerCheck(arguments: arguments, clientIdentifier: clientIdentifier))
        let listener = NSXPCListener.anonymous()
        listener.delegate = check
        listener.resume()
        defer { listener.invalidate() }
        let connection = NSXPCConnection(listenerEndpoint: listener.endpoint)
        connection.remoteObjectInterface = NSXPCInterface(with: HelperXPCProtocol.self)
        connection.resume()
        defer { connection.invalidate() }
        let outcome = await withCheckedContinuation { (continuation: CheckedContinuation<Outcome, Never>) in
            let once = Once(continuation)
            guard let proxy = connection.remoteObjectProxyWithErrorHandler({ @Sendable _ in once.finish(.refused) }) as? HelperXPCProtocol else {
                once.finish(.refused)
                return
            }
            proxy.version { helper, proto, mode in once.finish(.answered(Version(helper: helper, proto: proto, mode: mode))) }
            // A dedicated thread, so the timeout fires even if the dispatch pools are busy.
            Thread.detachNewThread {
                Thread.sleep(forTimeInterval: 10)
                once.finish(.timedOut)
            }
        }
        #expect(outcome != .timedOut, "neither an answer nor an error within 10 seconds")
        if case .answered(let version) = outcome { return version }
        return nil
    }

    @Test func testUIDOnlyAcceptsTheAllowedUser() async throws {
        let version = try await ask(try HelperLaunchArguments(allowedUID: getuid(), callerCheck: .uidOnly))
        #expect(version == Version(helper: HelperTransport.helperVersion, proto: HelperTransport.protocolVersion, mode: "uid-only"))
    }

    @Test func testAnotherUserIsRefused() async throws {
        #expect(try await ask(try HelperLaunchArguments(allowedUID: getuid() + 1, callerCheck: .uidOnly)) == nil)
        // Root is not special: the helper serves exactly one UID.
        if getuid() != 0 {
            #expect(try await ask(try HelperLaunchArguments(allowedUID: 0, callerCheck: .uidOnly)) == nil)
        }
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
        #expect(CallerCheck(arguments: signed, clientIdentifier: "bad\" or anchor apple") == nil)
        #expect(CallerCheck(arguments: signed, clientIdentifier: "") == nil)
    }
}
