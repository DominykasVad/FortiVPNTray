import Testing
import Foundation
import FortiVPNShared
@testable import FortiVPNHelper

struct SessionControllerTests {
    /// Records calls; fails `start` when told to.
    private final class MockLauncher: TunnelLauncher, @unchecked Sendable {
        // @unchecked Sendable: all fields are only touched while holding `lock`.
        struct Failure: Error, CustomStringConvertible { var description: String { "mock start failed" } }
        private let lock = NSLock()
        private var _starts: [String] = []
        private var _stops = 0
        private let fails: Bool
        init(fails: Bool = false) { self.fails = fails }
        var starts: [String] { lock.withLock { _starts } }
        var stops: Int { lock.withLock { _stops } }
        func start(_ request: ConnectRequest, sessionID: String) throws {
            lock.withLock { _starts.append(sessionID) }
            if fails { throw Failure() }
        }
        func stop() { lock.withLock { _stops += 1 } }
    }

    private let request = try! ConnectRequest(host: "vpn.example.com", port: 443)
    private let start = Date(timeIntervalSince1970: 1_700_000_000)

    @Test func testConnectStartsOneSession() throws {
        let launcher = MockLauncher()
        let start = start
        let sessions = SessionController(launcher: launcher, now: { start })
        let id = try sessions.connect(request)
        #expect(UUID(uuidString: id) != nil)
        #expect(launcher.starts == [id])
        #expect(sessions.status() == HelperStatus(state: .connecting, sessionID: id, since: start))
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
        _ = try sessions.connect(request)
        sessions.disconnect()
        #expect(launcher.stops == 1)
        #expect(sessions.status() == HelperStatus())
        // Nothing running: disconnect does nothing.
        sessions.disconnect()
        #expect(launcher.stops == 1)
        _ = try sessions.connect(request)
        #expect(launcher.starts.count == 2)
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
        #expect(try sessions.readLog(sessionID: id, offset: 5) == LogChunk(lines: [], nextOffset: 5))
    }

    @Test func testUnavailableLauncherRefusesEveryStart() {
        let sessions = SessionController(launcher: UnavailableLauncher())
        #expect(throws: SessionController.Refusal.self) { try sessions.connect(request) }
        #expect(sessions.status().state == .idle)
        #expect(sessions.pendingSAMLURL() == nil)
    }
}
