import Testing
import Foundation
import FortiVPNShared
@testable import FortiVPNCore

/// The app's XPC client against a fake helper on an anonymous listener.
struct HelperXPCClientTests {
    /// Answers like the helper; `silent` never replies.
    private final class FakeHelper: NSObject, HelperXPCProtocol, NSXPCListenerDelegate, @unchecked Sendable {
        // @unchecked Sendable: `_accepted` and `_received` are only touched while holding `lock`.
        private let lock = NSLock()
        private var _accepted = 0
        private var _received: [Data] = []
        var accepted: Int { lock.withLock { _accepted } }
        var receivedRequests: [Data] { lock.withLock { _received } }
        var connectReply: (String?, String?) = ("6F0E6A5C-8E4B-4C1E-9D7A-2B3C4D5E6F70", nil)
        var disconnectError: String?
        var logReply: (Data?, String?) = (HelperWire.encode(LogChunk(lines: ["INFO:   Connected to gateway."], nextOffset: 1)), nil)
        var samlURL: String?
        let mode: String
        let status: Data
        let silent: Bool

        init(mode: String = CallerCheckMode.signed.rawValue, status: Data = HelperWire.encode(HelperStatus()), silent: Bool = false) {
            self.mode = mode
            self.status = status
            self.silent = silent
        }

        func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
            connection.exportedInterface = NSXPCInterface(with: HelperXPCProtocol.self)
            connection.exportedObject = self
            connection.resume()
            lock.withLock { _accepted += 1 }
            return true
        }

        func version(reply: @escaping @Sendable (String, Int, String) -> Void) {
            if !silent { reply("0.3.0", HelperTransport.protocolVersion, mode) }
        }
        func status(reply: @escaping @Sendable (Data) -> Void) {
            if !silent { reply(status) }
        }
        func connect(_ request: Data, reply: @escaping @Sendable (String?, String?) -> Void) {
            lock.withLock { _received.append(request) }
            reply(connectReply.0, connectReply.1)
        }
        func disconnect(reply: @escaping @Sendable (String?) -> Void) { reply(disconnectError) }
        func readLog(sessionID: String, offset: Int, reply: @escaping @Sendable (Data?, String?) -> Void) { reply(logReply.0, logReply.1) }
        func pendingSAMLURL(reply: @escaping @Sendable (String?) -> Void) { reply(samlURL) }
    }

    /// A client and the listener it talks to. The listener holds its delegate weakly,
    /// so the fixture keeps the fake helper alive.
    private struct Fixture {
        let client: HelperXPCClient
        let listener: NSXPCListener
        let helper: FakeHelper
        func invalidate() { listener.invalidate() }
    }

    private func fixture(_ helper: FakeHelper, timeout: TimeInterval = 5) -> Fixture {
        let listener = NSXPCListener.anonymous()
        listener.delegate = helper
        listener.resume()
        let endpoint = listener.endpoint
        return Fixture(client: HelperXPCClient(timeout: timeout) { NSXPCConnection(listenerEndpoint: endpoint) }, listener: listener, helper: helper)
    }

    /// Runs the blocking call on its own thread, so the test's task-pool thread stays free.
    private func offPool<Value: Sendable>(_ body: @escaping @Sendable () throws -> Value) async -> Result<Value, VPNError> {
        await withCheckedContinuation { continuation in
            Thread.detachNewThread {
                continuation.resume(returning: Result { try body() }.mapError { $0 as? VPNError ?? VPNError("\($0)") })
            }
        }
    }

    @Test func testVersion() async {
        let fixture = fixture(FakeHelper())
        defer { fixture.invalidate() }
        let client = fixture.client
        let result = await offPool { try client.version() }
        #expect(result == .success(HelperVersion(version: "0.3.0", protocolVersion: HelperTransport.protocolVersion, mode: .signed)))
    }

    @Test func testUIDOnlyMode() async {
        let fixture = fixture(FakeHelper(mode: "uid-only"))
        defer { fixture.invalidate() }
        let client = fixture.client
        #expect(await offPool { try client.version() }.map(\.mode) == .success(.uidOnly))
    }

    @Test func testUnknownModeIsAnError() async {
        let fixture = fixture(FakeHelper(mode: "trust-everyone"))
        defer { fixture.invalidate() }
        let client = fixture.client
        #expect(await offPool { try client.version() } == .failure(VPNError("The helper reported an unknown caller check.")))
    }

    @Test func testStatus() async {
        let active = HelperStatus(state: .connected, sessionID: UUID().uuidString)
        let fixture = fixture(FakeHelper(status: HelperWire.encode(active)))
        defer { fixture.invalidate() }
        let client = fixture.client
        #expect(await offPool { try client.status() } == .success(active))
        let brokenFixture = self.fixture(FakeHelper(status: Data("nope".utf8)))
        defer { brokenFixture.invalidate() }
        let broken = brokenFixture.client
        #expect(await offPool { try broken.status() } == .failure(VPNError("The helper sent an unreadable status.")))
    }

    @Test func testSilentHelperTimesOut() async {
        let fixture = fixture(FakeHelper(silent: true), timeout: 0.3)
        defer { fixture.invalidate() }
        let client = fixture.client
        #expect(await offPool { try client.version() } == .failure(VPNError("The helper did not answer in time.")))
    }

    /// No such service, as when the helper is not installed: an error at once, not a timeout.
    @Test func testNoHelperIsUnavailable() async {
        let name = "eu.dvad.fortivpntray.test.missing-\(UUID().uuidString)"
        let client = HelperXPCClient(timeout: 5) { NSXPCConnection(machServiceName: name, options: []) }
        let began = Date()
        let result = await offPool { try client.version() }
        #expect(result == .failure(VPNError("Helper unavailable. Install or repair it in Settings.")))
        #expect(Date().timeIntervalSince(began) < 4)
    }

    @Test func testConnectSendsTheRequestAsJSON() async throws {
        let fixture = fixture(FakeHelper())
        defer { fixture.invalidate() }
        let client = fixture.client
        let request = try ConnectRequest(host: "vpn.example.com", port: 443, realm: "staff")
        #expect(await offPool { try client.connect(request) } == .success("6F0E6A5C-8E4B-4C1E-9D7A-2B3C4D5E6F70"))
        #expect(fixture.helper.receivedRequests.count == 1)
        #expect(try ConnectRequest(json: fixture.helper.receivedRequests[0]) == request)
    }

    @Test func testHelperErrorsReachTheCaller() async throws {
        let helper = FakeHelper()
        helper.connectReply = (nil, "A session is already active.")
        helper.disconnectError = "Nope."
        helper.logReply = (nil, "Unknown session.")
        let fixture = fixture(helper)
        defer { fixture.invalidate() }
        let client = fixture.client
        let request = try ConnectRequest(host: "vpn.example.com", port: 443)
        #expect(await offPool { try client.connect(request) } == .failure(VPNError("A session is already active.")))
        #expect(await offPool { try client.disconnect() }.map { "ok" } == .failure(VPNError("Nope.")))
        #expect(await offPool { try client.readLog(sessionID: "x", offset: 0) } == .failure(VPNError("Unknown session.")))
    }

    @Test func testReadLogAndPendingSAMLURL() async {
        let helper = FakeHelper()
        helper.samlURL = "https://vpn.example.com:443/remote/saml/start?redirect=1"
        let fixture = fixture(helper)
        defer { fixture.invalidate() }
        let client = fixture.client
        #expect(await offPool { try client.readLog(sessionID: "x", offset: 0) } == .success(LogChunk(lines: ["INFO:   Connected to gateway."], nextOffset: 1)))
        #expect(await offPool { try client.pendingSAMLURL() } == .success(URL(string: "https://vpn.example.com:443/remote/saml/start?redirect=1")))
        #expect(await offPool { try client.disconnect() }.map { "ok" } == .success("ok"))
    }

    /// Polling must not open a connection (and make the helper check the caller) per call.
    @Test func testOneConnectionIsReused() async {
        let fixture = fixture(FakeHelper())
        defer { fixture.invalidate() }
        let client = fixture.client
        for _ in 0..<5 {
            _ = await offPool { try client.status() }
            _ = await offPool { try client.readLog(sessionID: "x", offset: 0) }
        }
        #expect(fixture.helper.accepted == 1)
    }
}
