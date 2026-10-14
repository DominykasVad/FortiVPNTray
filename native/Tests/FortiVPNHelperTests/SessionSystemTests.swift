import Testing
import Foundation
import FortiVPNShared
@testable import FortiVPNHelper

/// The session's system side (PLAN.md 2.5): state file, pppd, DNS, cleanup on
/// every exit path, sweeps. Fake processes and network only.
struct SessionSystemTests {
    private let request = try! ConnectRequest(host: "vpn.example.com", port: 443)

    /// Runs a session up to "tunnel up": DNS lines, the interface, pppd as a child of openfortivpn.
    private func connectAndComeUp(_ harness: Harness, dns: Bool = true) throws -> (id: String, pppd: ProcessIdentity) {
        let id = try harness.sessions.connect(request)
        let openfortivpn = try #require(harness.launcher.child(of: id))
        let pppd = harness.processes.spawn(TunnelCleanup.pppdPath, parent: openfortivpn.pid)
        if dns {
            harness.launcher.send(.output("DEBUG:  Found dns server 192.0.2.53 in xml config"), to: id)
            harness.launcher.send(.output("DEBUG:  Found dns suffix corp.example.com in xml config"), to: id)
        }
        harness.launcher.send(.output("INFO:   Got addresses: [192.0.2.200], ns [192.0.2.53]"), to: id)
        harness.launcher.send(.output("INFO:   Interface ppp0 is UP."), to: id)
        harness.launcher.send(.output("INFO:   Tunnel is up and running."), to: id)
        harness.launcher.send(.tunnelUp, to: id)
        return (id, pppd)
    }

    @Test func testStateIsSavedBeforeTheChildAndCompletedAsTheSessionRuns() throws {
        let harness = try Harness(launcher: MockLauncher(holdsStart: true))
        let sessions = harness.sessions
        let request = request
        let connect = onThread { SessionControllerTests.attempt { try sessions.connect(request) } }
        #expect(harness.launcher.waitUntilStartEntered())
        // Saved before start() was called: the routes can be undone even if the helper dies now.
        let early = try #require(try harness.saved())
        #expect(early.serverIP == "198.51.100.7" && early.gateway == "192.0.2.1" && early.openfortivpn == nil)
        harness.launcher.releaseStart()
        let id = try #require(try connect()?.get())
        #expect(try harness.saved()?.openfortivpn == harness.launcher.child(of: id))

        let pppd = harness.processes.spawn(TunnelCleanup.pppdPath, parent: try #require(harness.launcher.child(of: id)).pid)
        harness.launcher.send(.output("INFO:   Interface ppp0 is UP."), to: id)
        let saved = try #require(try harness.saved())
        #expect(saved.pppd == pppd, "pppd recorded while openfortivpn runs")
        #expect(saved.interface == "ppp0")
        #expect(saved.sessionID == id && !saved.dnsApplied)
    }

    @Test func testTunnelUpAppliesTheTunnelsDNS() throws {
        let harness = try Harness()
        let (id, _) = try connectAndComeUp(harness)
        #expect(harness.network.dns == (try DNSConfiguration(servers: ["192.0.2.53"], domains: ["corp.example.com"])))
        #expect(try harness.saved()?.dnsApplied == true)
        #expect(harness.sessions.status() == HelperStatus(state: .connected, sessionID: id, interface: "ppp0", vpnIP: "192.0.2.200",
                                                          since: harness.sessions.status().since))
    }

    @Test func testSystemResolversAreTheFallbackOnlyWhenAskedFor() throws {
        let fallback = try Harness()
        _ = try connectAndComeUp(fallback, dns: false)
        #expect(fallback.network.dns == (try DNSConfiguration(servers: ["192.0.2.53"], domains: [])))

        let none = try Harness()
        let id = try none.sessions.connect(try ConnectRequest(host: "vpn.example.com", port: 443, useSystemDNSFallback: false))
        none.launcher.send(.tunnelUp, to: id)
        #expect(none.network.dns == nil)
        #expect(!none.network.calls.contains { if case .setDNS = $0 { return true } else { return false } })
        #expect(try none.saved()?.dnsApplied == false)
    }

    @Test func testDisconnectCleansUpEverythingAndRemovesTheState() throws {
        let harness = try Harness()
        let (id, pppd) = try connectAndComeUp(harness)
        // openfortivpn pointed the default route at the tunnel.
        harness.network.currentDefaultRoute = DefaultRoute(gateway: nil, interface: "ppp0")
        let openfortivpn = try #require(harness.launcher.child(of: id))
        harness.sessions.disconnect()
        #expect(harness.sessions.status() == HelperStatus())
        #expect(!harness.processes.isAlive(openfortivpn.pid) && !harness.processes.isAlive(pppd.pid))
        #expect(harness.processes.signals == [.init(pid: openfortivpn.pid, signal: SIGINT), .init(pid: pppd.pid, signal: SIGTERM)])
        #expect(Array(harness.network.calls.suffix(4)) == [.replaceDefaultRoute("192.0.2.1"), .deleteHostRoute("198.51.100.7"), .removeDNS, .flushDNSCache])
        #expect(harness.network.dns == nil)
        #expect(!harness.state.exists)
    }

    @Test func testUnexpectedExitCleansUpAndReportsTheExit() throws {
        let harness = try Harness()
        let (id, pppd) = try connectAndComeUp(harness)
        harness.launcher.send(.exited(.signal(SIGKILL)), to: id)
        #expect(harness.sessions.status() == HelperStatus(lastError: "openfortivpn was ended by signal 9."))
        // pppd was recorded while openfortivpn ran, so it is stopped although it is no longer its child.
        #expect(!harness.processes.isAlive(pppd.pid))
        #expect(harness.network.calls.contains(.deleteHostRoute("198.51.100.7")) && harness.network.dns == nil)
        #expect(harness.launcher.stops == 0)
        #expect(!harness.state.exists)
    }

    @Test func testExitBeforeStartReturnsCleansUp() throws {
        let harness = try Harness(launcher: MockLauncher(holdsStart: true))
        let sessions = harness.sessions
        let request = request
        let connect = onThread { SessionControllerTests.attempt { try sessions.connect(request) } }
        #expect(harness.launcher.waitUntilStartEntered())
        let id = try #require(sessions.status().sessionID)
        harness.launcher.send(.exited(.status(1)), to: id)
        harness.launcher.releaseStart()
        #expect(try #require(connect()) == .failure(.init(description: "openfortivpn exited with status 1.")))
        #expect(harness.network.calls.contains(.deleteHostRoute("198.51.100.7")))
        #expect(!harness.state.exists)
    }

    @Test func testDisconnectWhileStartingCleansUpAfterStartReturns() throws {
        let harness = try Harness(launcher: MockLauncher(holdsStart: true))
        let sessions = harness.sessions
        let request = request
        let connect = onThread { SessionControllerTests.attempt { try sessions.connect(request) } }
        #expect(harness.launcher.waitUntilStartEntered())
        sessions.disconnect()
        #expect(harness.state.exists, "nothing is cleaned up while start() runs")
        harness.launcher.releaseStart()
        #expect(try #require(connect()) == .failure(.init(description: SessionController.disconnectedWhileStarting)))
        #expect(harness.launcher.running.isEmpty)
        #expect(!harness.state.exists)
    }

    /// Without a saved state a crash could not be undone, so nothing is started.
    @Test func testConnectIsRefusedIfTheStateCannotBeSaved() throws {
        let harness = try Harness()
        try harness.state.store.directory.prepare()
        chmod(harness.state.store.directory.path, 0o755)
        #expect(throws: SessionController.Refusal.self) { try harness.sessions.connect(request) }
        #expect(harness.launcher.calls.isEmpty)
        #expect(harness.sessions.status().state == .idle)
        #expect(harness.sessions.status().lastError?.hasPrefix("Cannot save the session state") == true)
    }

    @Test func testFailedStartLeavesNoState() throws {
        let harness = try Harness(launcher: MockLauncher(fails: true))
        #expect(throws: SessionController.Refusal.self) { try harness.sessions.connect(request) }
        #expect(!harness.state.exists)
    }

    @Test func testNoDNSIsAppliedOnceTheSessionIsEnding() throws {
        let harness = try Harness(launcher: MockLauncher(holdsStart: true))
        let sessions = harness.sessions
        let request = request
        let connect = onThread { SessionControllerTests.attempt { try sessions.connect(request) } }
        #expect(harness.launcher.waitUntilStartEntered())
        let id = try #require(sessions.status().sessionID)
        sessions.disconnect()
        harness.launcher.send(.tunnelUp, to: id)
        harness.launcher.releaseStart()
        _ = connect()
        #expect(harness.network.dns == nil)
        #expect(!harness.network.calls.contains { if case .setDNS = $0 { return true } else { return false } })
    }

    // MARK: Sweeps

    /// What an earlier helper run left: its openfortivpn and pppd still running, the state on disk.
    private func leftover(_ harness: Harness) throws -> (TunnelState, ProcessIdentity, ProcessIdentity) {
        let openfortivpn = harness.processes.spawn(MockLauncher.executable)
        let pppd = harness.processes.spawn(TunnelCleanup.pppdPath, parent: openfortivpn.pid)
        var state = TunnelState(sessionID: UUID().uuidString, serverIP: "198.51.100.9", gateway: "192.0.2.1")
        state.openfortivpn = openfortivpn
        state.pppd = pppd
        state.interface = "ppp0"
        state.dnsApplied = true
        try harness.state.store.save(state)
        return (state, openfortivpn, pppd)
    }

    @Test func testSweepUndoesAnEarlierRunFromTheStateFile() throws {
        let harness = try Harness()
        let (_, openfortivpn, pppd) = try leftover(harness)
        harness.sessions.sweep()
        #expect(!harness.processes.isAlive(openfortivpn.pid) && !harness.processes.isAlive(pppd.pid))
        #expect(harness.network.calls == [.deleteHostRoute("198.51.100.9"), .removeDNS, .flushDNSCache])
        #expect(!harness.state.exists)
        harness.sessions.sweep()
        #expect(harness.network.calls.count == 3, "nothing left to sweep")
    }

    @Test func testConnectSweepsFirst() throws {
        let harness = try Harness()
        let (_, openfortivpn, _) = try leftover(harness)
        let id = try harness.sessions.connect(request)
        #expect(!harness.processes.isAlive(openfortivpn.pid))
        #expect(harness.network.calls.first == .deleteHostRoute("198.51.100.9"))
        #expect(try harness.saved()?.sessionID == id, "the new session's state replaced the old")
    }

    @Test func testSweepWithExitedProcessesSignalsNothing() throws {
        let harness = try Harness()
        let (_, openfortivpn, pppd) = try leftover(harness)
        harness.processes.exit(openfortivpn.pid)
        harness.processes.exit(pppd.pid)
        harness.processes.reuse(pppd.pid, executable: TunnelCleanup.pppdPath)
        harness.sessions.sweep()
        #expect(harness.processes.signals.isEmpty)
        #expect(harness.processes.isAlive(pppd.pid))
        #expect(harness.network.calls == [.deleteHostRoute("198.51.100.9"), .removeDNS, .flushDNSCache])
        #expect(!harness.state.exists)
    }

    @Test func testAnInvalidStateFileIsLeftAloneAndNothingIsUndone() throws {
        let harness = try Harness()
        let (_, openfortivpn, _) = try leftover(harness)
        try Data("{\"sessionID\": \"x\", \"dnsApplied\": true}".utf8).write(to: URL(fileURLWithPath: harness.state.store.path))
        harness.sessions.sweep()
        #expect(harness.processes.signals.isEmpty && harness.network.calls.isEmpty)
        #expect(harness.processes.isAlive(openfortivpn.pid))
        #expect(harness.state.exists)
        // A connect still works; its own state replaces the bad file.
        let id = try harness.sessions.connect(request)
        #expect(try harness.saved()?.sessionID == id)
    }
}
