import Testing
import Foundation
import FortiVPNShared
@testable import FortiVPNHelper

/// A launcher whose child is imaginary: records calls, can fail, can hold `start`
/// open until released, and lets the test send events as the child would.
final class MockLauncher: TunnelLauncher, @unchecked Sendable {
    // @unchecked Sendable: all fields are only touched while holding `lock`.
    struct Failure: Error, CustomStringConvertible { var description: String { "mock start failed" } }
    enum Call: Equatable { case startEntered(String), startReturned(String), stop(String) }

    private let lock = NSLock()
    private var _calls: [Call] = []
    private var _running: Set<String> = []
    private var _onEvent: [String: @Sendable (TunnelEvent) -> Void] = [:]
    private let fails: Bool
    /// When set, `start` signals `entered` and waits for `release` before returning.
    private let gate: (entered: DispatchSemaphore, release: DispatchSemaphore)?

    init(fails: Bool = false, holdsStart: Bool = false) {
        self.fails = fails
        gate = holdsStart ? (DispatchSemaphore(value: 0), DispatchSemaphore(value: 0)) : nil
    }

    var calls: [Call] { lock.withLock { _calls } }
    var starts: [String] { calls.compactMap { if case .startReturned(let id) = $0 { return id } else { return nil } } }
    var stops: Int { calls.filter { if case .stop = $0 { return true } else { return false } }.count }
    /// Sessions whose imaginary child is running.
    var running: Set<String> { lock.withLock { _running } }

    func waitUntilStartEntered() -> Bool { gate?.entered.wait(timeout: .now() + 10) == .success }
    func releaseStart() { gate?.release.signal() }

    func send(_ event: TunnelEvent, to sessionID: String) {
        let handler = lock.withLock { () -> (@Sendable (TunnelEvent) -> Void)? in
            if case .exited = event { _running.remove(sessionID) }
            return _onEvent[sessionID]
        }
        handler?(event)
    }

    func start(_ request: ConnectRequest, sessionID: String, onEvent: @escaping @Sendable (TunnelEvent) -> Void) throws {
        lock.withLock {
            _calls.append(.startEntered(sessionID))
            _onEvent[sessionID] = onEvent
        }
        if fails { throw Failure() }
        // The child is spawned here, before start returns.
        lock.withLock { _ = _running.insert(sessionID) }
        if let gate {
            gate.entered.signal()
            _ = gate.release.wait(timeout: .now() + 10)
        }
        lock.withLock { _calls.append(.startReturned(sessionID)) }
    }

    func stop(sessionID: String) {
        lock.withLock {
            _calls.append(.stop(sessionID))
            _running.remove(sessionID)
        }
    }
}

/// Runs `body` on its own thread, so a test can block on it without holding a task-pool thread.
func onThread<Value: Sendable>(_ body: @escaping @Sendable () -> Value) -> @Sendable () -> Value? {
    let done = DispatchSemaphore(value: 0)
    let box = Box<Value>()
    Thread.detachNewThread {
        box.value = body()
        done.signal()
    }
    return { done.wait(timeout: .now() + 15) == .success ? box.value : nil }
}

final class Box<Value: Sendable>: @unchecked Sendable {
    // @unchecked Sendable: `_value` is only touched while holding `lock`.
    private let lock = NSLock()
    private var _value: Value?
    var value: Value? {
        get { lock.withLock { _value } }
        set { lock.withLock { _value = newValue } }
    }
}

struct SessionControllerTests {
    private let request = try! ConnectRequest(host: "vpn.example.com", port: 443)
    private let start = Date(timeIntervalSince1970: 1_700_000_000)

    static func attempt(_ body: () throws -> String) -> Result<String, SessionController.Refusal> {
        do { return .success(try body()) } catch let refusal as SessionController.Refusal { return .failure(refusal) } catch {
            return .failure(.init(description: "unexpected: \(error)"))
        }
    }

    @Test func testConnectStartsOneSession() throws {
        let launcher = MockLauncher()
        let start = start
        let sessions = SessionController(launcher: launcher, now: { start })
        let id = try sessions.connect(request)
        #expect(UUID(uuidString: id) != nil)
        #expect(launcher.starts == [id])
        #expect(sessions.status() == HelperStatus(state: .connecting, sessionID: id, since: start))
        launcher.send(.tunnelUp, to: id)
        #expect(sessions.status() == HelperStatus(state: .connected, sessionID: id, since: start))
    }

    @Test func testSecondConnectIsRefusedWhileActive() throws {
        let launcher = MockLauncher()
        let sessions = SessionController(launcher: launcher)
        let id = try sessions.connect(request)
        #expect(throws: SessionController.Refusal(description: "A session is already active.")) { try sessions.connect(request) }
        #expect(launcher.starts == [id])
        #expect(sessions.status().sessionID == id)
    }

    @Test func testConcurrentConnectsStartExactlyOne() async {
        let launcher = MockLauncher()
        let sessions = SessionController(launcher: launcher)
        let request = request
        let started = await withTaskGroup(of: Bool.self) { group in
            for _ in 0..<32 { group.addTask { (try? sessions.connect(request)) != nil } }
            return await group.reduce(0) { $0 + ($1 ? 1 : 0) }
        }
        #expect(started == 1)
        #expect(launcher.starts.count == 1)
    }

    @Test func testFailedStartFreesTheSlotAndReportsTheError() throws {
        let sessions = SessionController(launcher: MockLauncher(fails: true))
        #expect(throws: SessionController.Refusal(description: "mock start failed")) { try sessions.connect(request) }
        #expect(sessions.status() == HelperStatus(state: .idle, lastError: "mock start failed"))
        #expect(throws: SessionController.Refusal.self) { try sessions.connect(request) }
    }

    @Test func testDisconnectStopsAndAllowsANewSession() throws {
        let launcher = MockLauncher()
        let sessions = SessionController(launcher: launcher)
        let id = try sessions.connect(request)
        sessions.disconnect()
        #expect(launcher.calls == [.startEntered(id), .startReturned(id), .stop(id)])
        #expect(launcher.running.isEmpty)
        #expect(sessions.status() == HelperStatus())
        // Nothing running: disconnect does nothing.
        sessions.disconnect()
        #expect(launcher.stops == 1)
        _ = try sessions.connect(request)
        #expect(launcher.starts.count == 2)
    }

    /// The review case: disconnect arrives while start() is still running, after the
    /// child was spawned and before start() returned. The stop waits for start() and
    /// the child is not left running.
    @Test func testDisconnectWhileStartIsRunningStopsTheChildAfterStartReturns() throws {
        let launcher = MockLauncher(holdsStart: true)
        let sessions = SessionController(launcher: launcher)
        let request = request
        let connect = onThread { Self.attempt { try sessions.connect(request) } }
        #expect(launcher.waitUntilStartEntered())
        let id = try #require(sessions.status().sessionID)
        #expect(sessions.status().state == .connecting)
        #expect(launcher.running == [id])

        sessions.disconnect()
        // Recorded, not acted on: stop() never runs alongside start().
        #expect(sessions.status() == HelperStatus(state: .disconnecting, sessionID: id, since: sessions.status().since))
        #expect(launcher.stops == 0)
        // A second disconnect and a new connect change nothing while it unwinds.
        sessions.disconnect()
        #expect(throws: SessionController.Refusal(description: "A session is already active.")) { try sessions.connect(request) }

        launcher.releaseStart()
        let outcome = try #require(connect())
        #expect(outcome == .failure(SessionController.Refusal(description: SessionController.disconnectedWhileStarting)))
        #expect(launcher.calls == [.startEntered(id), .startReturned(id), .stop(id)])
        #expect(launcher.running.isEmpty)
        #expect(sessions.status() == HelperStatus())
        launcher.releaseStart()   // Let the next start through without holding it.
        _ = try sessions.connect(request)
    }

    @Test func testDisconnectWhileStartFailsStopsNothing() throws {
        let launcher = MockLauncher(fails: true)
        let sessions = SessionController(launcher: launcher)
        #expect(throws: SessionController.Refusal.self) { try sessions.connect(request) }
        sessions.disconnect()
        #expect(launcher.stops == 0)
    }

    @Test func testChildExitWhileRunningEndsTheSession() throws {
        let launcher = MockLauncher()
        let sessions = SessionController(launcher: launcher)
        let id = try sessions.connect(request)
        launcher.send(.exited(.status(1)), to: id)
        #expect(sessions.status() == HelperStatus(lastError: "openfortivpn exited with status 1."))
        sessions.disconnect()
        #expect(launcher.stops == 0)
        // Events for a session that is over are ignored.
        launcher.send(.tunnelUp, to: id)
        #expect(sessions.status().state == .idle)
    }

    @Test func testChildExitBeforeStartReturnsFailsTheConnect() throws {
        let launcher = MockLauncher(holdsStart: true)
        let sessions = SessionController(launcher: launcher)
        let request = request
        let connect = onThread { Self.attempt { try sessions.connect(request) } }
        #expect(launcher.waitUntilStartEntered())
        let id = try #require(sessions.status().sessionID)
        launcher.send(.exited(.signal(9)), to: id)
        #expect(sessions.status().state == .connecting)
        launcher.releaseStart()
        #expect(try #require(connect()) == .failure(SessionController.Refusal(description: "openfortivpn was ended by signal 9.")))
        #expect(sessions.status() == HelperStatus(lastError: "openfortivpn was ended by signal 9."))
        #expect(launcher.stops == 0)
    }

    @Test func testReadLogOnlyForTheCurrentOrLastSession() throws {
        let sessions = SessionController(launcher: MockLauncher())
        #expect(throws: SessionController.Refusal(description: "Unknown session.")) { try sessions.readLog(sessionID: "", offset: 0) }
        let id = try sessions.connect(request)
        #expect(try sessions.readLog(sessionID: id, offset: 0) == LogChunk(lines: [], nextOffset: 0))
        #expect(throws: SessionController.Refusal(description: "The log offset must not be negative.")) {
            try sessions.readLog(sessionID: id, offset: -1)
        }
        #expect(throws: SessionController.Refusal(description: "Unknown session.")) {
            try sessions.readLog(sessionID: UUID().uuidString, offset: 0)
        }
        sessions.disconnect()
        // Past the end of the (empty) log: nothing, and where to continue.
        #expect(try sessions.readLog(sessionID: id, offset: 5) == LogChunk(lines: [], nextOffset: 0))
        #expect(sessions.pendingSAMLURL() == nil)
    }

    @Test func testOutputIsKeptRedacted() throws {
        let launcher = MockLauncher()
        let sessions = SessionController(launcher: launcher)
        let id = try sessions.connect(request)
        launcher.send(.output("INFO:   Connected to gateway."), to: id)
        launcher.send(.output("DEBUG:  Cookie: SVPNCOOKIE=4f1d0c9a8b7e6d5c"), to: id)
        launcher.send(.output("DEBUG:  Using SAML authentication URL /remote/saml/auth_id?id=0123456789abcdef"), to: id)
        #expect(try sessions.readLog(sessionID: id, offset: 0) == LogChunk(lines: [
            "INFO:   Connected to gateway.",
            "DEBUG:  Cookie: [redacted]",
            "DEBUG:  Using SAML authentication URL [redacted]",
        ], nextOffset: 3))
        #expect(try sessions.readLog(sessionID: id, offset: 3) == LogChunk(lines: [], nextOffset: 3))
    }

    /// The child's last lines can arrive after its exit was reported (the pipe and
    /// the termination handler are separate); they belong to the last session's log.
    @Test func testLinesAfterTheChildExitedAreKeptForTheLastSession() throws {
        let launcher = MockLauncher()
        let sessions = SessionController(launcher: launcher)
        let id = try sessions.connect(request)
        launcher.send(.output("INFO:   Connected to gateway."), to: id)
        launcher.send(.exited(.status(1)), to: id)
        launcher.send(.output("ERROR:  Could not authenticate to gateway. Please check the password, client certificate, etc."), to: id)
        launcher.send(.output("INFO:   Closed connection to gateway."), to: id)
        #expect(sessions.status() == HelperStatus(lastError: "openfortivpn exited with status 1."))
        #expect(try sessions.readLog(sessionID: id, offset: 0).lines == [
            "INFO:   Connected to gateway.",
            "ERROR:  Could not authenticate to gateway. Please check the password, client certificate, etc.",
            "INFO:   Closed connection to gateway.",
        ])
    }

    @Test func testLinesAfterADisconnectAreKeptForTheLastSession() throws {
        let launcher = MockLauncher()
        let sessions = SessionController(launcher: launcher)
        let id = try sessions.connect(request)
        sessions.disconnect()
        launcher.send(.output("INFO:   Terminated."), to: id)
        #expect(try sessions.readLog(sessionID: id, offset: 0).lines == ["INFO:   Terminated."])
    }

    @Test func testANewSessionReplacesTheLogAndDropsTheOldOnesLateLines() throws {
        let launcher = MockLauncher()
        let sessions = SessionController(launcher: launcher)
        let first = try sessions.connect(request)
        launcher.send(.output("first"), to: first)
        sessions.disconnect()
        let second = try sessions.connect(request)
        launcher.send(.output("late line of the first session"), to: first)
        launcher.send(.output("second"), to: second)
        #expect(throws: SessionController.Refusal(description: "Unknown session.")) { try sessions.readLog(sessionID: first, offset: 0) }
        #expect(try sessions.readLog(sessionID: second, offset: 0).lines == ["second"])
    }

    @Test func testSAMLStartURLMatchesOpenFortiVPN() throws {
        #expect(SessionController.samlStartURL(for: request) == "https://vpn.example.com:443/remote/saml/start?redirect=1")
        let realm = try ConnectRequest(host: "192.0.2.10", port: 10443, realm: "Staff_VPN-1.x")
        #expect(SessionController.samlStartURL(for: realm) == "https://192.0.2.10:10443/remote/saml/start?redirect=1&realm=Staff_VPN-1.x")
    }

    @Test func testPendingSAMLURLOnlyOnceTheChildPrintedExactlyIt() throws {
        let launcher = MockLauncher()
        let sessions = SessionController(launcher: launcher)
        let request = try ConnectRequest(host: "vpn.example.com", port: 443, realm: "staff")
        let id = try sessions.connect(request)
        #expect(sessions.pendingSAMLURL() == nil)
        // Anything other than the URL built from the request is not offered.
        for line in [
            "INFO:   Authenticate at 'https://attacker.example.net:443/remote/saml/start?redirect=1&realm=staff'",
            "INFO:   Authenticate at 'https://vpn.example.com:443/remote/saml/start?redirect=1&realm=staff&x=1'",
            "INFO:   Authenticate at 'https://vpn.example.com:443/remote/saml/start?redirect=1'",
            "DEBUG:  Authenticate at 'https://vpn.example.com:443/remote/saml/start?redirect=1&realm=staff'",
        ] {
            launcher.send(.output(line), to: id)
            #expect(sessions.pendingSAMLURL() == nil, "\(line)")
        }
        launcher.send(.output("INFO:   Authenticate at 'https://vpn.example.com:443/remote/saml/start?redirect=1&realm=staff'"), to: id)
        #expect(sessions.pendingSAMLURL() == URL(string: "https://vpn.example.com:443/remote/saml/start?redirect=1&realm=staff"))
        // The log has the line, without the URL.
        #expect(try sessions.readLog(sessionID: id, offset: 0).lines.last == "INFO:   Authenticate at '[redacted]")
        launcher.send(.tunnelUp, to: id)
        #expect(sessions.pendingSAMLURL() == nil)
    }

    @Test func testPendingSAMLURLEndsWithTheSession() throws {
        let launcher = MockLauncher()
        let sessions = SessionController(launcher: launcher)
        let id = try sessions.connect(request)
        launcher.send(.output("INFO:   Authenticate at 'https://vpn.example.com:443/remote/saml/start?redirect=1'"), to: id)
        #expect(sessions.pendingSAMLURL() != nil)
        sessions.disconnect()
        #expect(sessions.pendingSAMLURL() == nil)
    }

    @Test func testNoPendingSAMLURLWhileDisconnecting() throws {
        let launcher = MockLauncher(holdsStart: true)
        let sessions = SessionController(launcher: launcher)
        let request = request
        let connect = onThread { Self.attempt { try sessions.connect(request) } }
        #expect(launcher.waitUntilStartEntered())
        let id = try #require(sessions.status().sessionID)
        launcher.send(.output("INFO:   Authenticate at 'https://vpn.example.com:443/remote/saml/start?redirect=1'"), to: id)
        #expect(sessions.pendingSAMLURL() != nil)
        sessions.disconnect()
        #expect(sessions.status().state == .disconnecting)
        #expect(sessions.pendingSAMLURL() == nil)
        launcher.releaseStart()
        _ = connect()
    }
}
