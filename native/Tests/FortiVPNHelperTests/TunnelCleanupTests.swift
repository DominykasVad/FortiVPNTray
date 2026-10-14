import Testing
import Foundation
@testable import FortiVPNHelper

/// `TunnelCleanup` against a fake process table and network (PLAN.md 2.5).
struct TunnelCleanupTests {
    static let openfortivpnPath = MockLauncher.executable

    /// openfortivpn with its pppd child, and the state a running session records.
    private struct Scene {
        let processes = FakeProcessTable()
        let network = FakeNetwork(defaultRoute: DefaultRoute(gateway: nil, interface: "ppp0"))
        let openfortivpn: ProcessIdentity
        let pppd: ProcessIdentity
        var state: TunnelState
        var cleanup: TunnelCleanup { TunnelCleanup(processes: processes, network: network, grace: 0.05) }

        init(pppdIgnores: Set<Int32> = []) throws {
            openfortivpn = processes.spawn(TunnelCleanupTests.openfortivpnPath)
            pppd = processes.spawn(TunnelCleanup.pppdPath, parent: openfortivpn.pid, ignoring: pppdIgnores)
            state = TunnelState(sessionID: TunnelStateTests.sessionID, serverIP: "198.51.100.7", gateway: "192.0.2.1")
            state.openfortivpn = openfortivpn
            state.pppd = pppd
            state.interface = "ppp0"
            state.dnsApplied = true
            try network.setDNS(DNSConfiguration(servers: ["192.0.2.53"], domains: []))
        }
    }

    @Test func testFullCleanup() throws {
        let scene = try Scene()
        scene.cleanup.run(scene.state)
        #expect(scene.processes.signals == [.init(pid: scene.openfortivpn.pid, signal: SIGINT), .init(pid: scene.pppd.pid, signal: SIGTERM)])
        #expect(!scene.processes.isAlive(scene.openfortivpn.pid) && !scene.processes.isAlive(scene.pppd.pid))
        #expect(scene.network.calls.dropFirst() == [.replaceDefaultRoute("192.0.2.1"), .deleteHostRoute("198.51.100.7"), .removeDNS, .flushDNSCache])
        #expect(scene.network.dns == nil)
    }

    @Test func testStopChildRunsAfterPPPDIsFoundAndBeforeTheRest() throws {
        var scene = try Scene()
        scene.state.pppd = nil
        let processes = scene.processes
        let openfortivpn = scene.openfortivpn
        let callsBefore = scene.network.calls.count
        let network = scene.network
        var seen: (pppdChildren: [pid_t], networkCalls: Int)?
        scene.cleanup.run(scene.state) {
            seen = (processes.children(of: openfortivpn.pid), network.calls.count)
            processes.send(SIGINT, to: openfortivpn.pid)
        }
        #expect(seen?.pppdChildren == [scene.pppd.pid])
        #expect(seen?.networkCalls == callsBefore, "nothing on the network happens before the child is stopped")
        // pppd was found while openfortivpn was alive, so it is stopped although it is no longer its child.
        #expect(scene.processes.signals.last == .init(pid: scene.pppd.pid, signal: SIGTERM))
        #expect(!scene.processes.isAlive(scene.pppd.pid))
    }

    /// The case from the #13 review: openfortivpn was SIGKILLed and its pppd reparented
    /// to launchd. The recorded pppd is still stopped.
    @Test func testRecordedPPPDIsStoppedAfterOpenFortiVPNIsGone() throws {
        let scene = try Scene()
        scene.processes.exit(scene.openfortivpn.pid)
        #expect(scene.processes.children(of: scene.openfortivpn.pid) == [])
        scene.cleanup.run(scene.state)
        #expect(scene.processes.signals == [.init(pid: scene.pppd.pid, signal: SIGTERM)])
        #expect(!scene.processes.isAlive(scene.pppd.pid))
    }

    @Test func testStubbornPPPDIsKilled() throws {
        let scene = try Scene(pppdIgnores: [SIGTERM])
        scene.cleanup.run(scene.state)
        #expect(Array(scene.processes.signals.suffix(2)) == [.init(pid: scene.pppd.pid, signal: SIGTERM), .init(pid: scene.pppd.pid, signal: SIGKILL)])
        #expect(!scene.processes.isAlive(scene.pppd.pid))
    }

    @Test func testExitedOrReusedPIDsAreNotSignalledAndTheRestStillRuns() throws {
        let scene = try Scene()
        scene.processes.exit(scene.openfortivpn.pid)
        scene.processes.exit(scene.pppd.pid)
        scene.processes.reuse(scene.pppd.pid, executable: TunnelCleanup.pppdPath)
        scene.cleanup.run(scene.state)
        #expect(scene.processes.signals.isEmpty)
        #expect(scene.processes.isAlive(scene.pppd.pid), "the process that now has pppd's PID is untouched")
        // The interface is no longer ours, so the default route is left alone.
        #expect(scene.network.calls.dropFirst() == [.deleteHostRoute("198.51.100.7"), .removeDNS, .flushDNSCache])
    }

    @Test func testPPPDIsFoundOnlyAsAChildRunningPPPD() throws {
        let processes = FakeProcessTable()
        let openfortivpn = processes.spawn(Self.openfortivpnPath)
        let elsewhere = processes.spawn(TunnelCleanup.pppdPath)                                  // someone else's pppd
        let impostor = processes.spawn("/tmp/pppd", parent: openfortivpn.pid)                   // named pppd, wrong path
        let cleanup = TunnelCleanup(processes: processes, network: FakeNetwork(), grace: 0.05)
        #expect(cleanup.findPPPD(of: openfortivpn) == nil)
        let pppd = processes.spawn(TunnelCleanup.pppdPath, parent: openfortivpn.pid)
        #expect(cleanup.findPPPD(of: openfortivpn) == pppd)
        processes.exit(openfortivpn.pid)
        #expect(cleanup.findPPPD(of: openfortivpn) == nil, "no lookup once openfortivpn is gone")

        var state = TunnelState(sessionID: TunnelStateTests.sessionID, serverIP: nil, gateway: nil)
        state.openfortivpn = openfortivpn
        cleanup.run(state)
        #expect(processes.signals.isEmpty)
        #expect(processes.isAlive(elsewhere.pid) && processes.isAlive(impostor.pid) && processes.isAlive(pppd.pid))
    }

    @Test func testDefaultRouteIsRestoredOnlyIfItPointsAtTheSessionsInterface() throws {
        let elsewhere = try Scene()
        elsewhere.network.currentDefaultRoute = DefaultRoute(gateway: "203.0.113.1", interface: "en5")
        elsewhere.cleanup.run(elsewhere.state)
        #expect(!elsewhere.network.calls.contains(.replaceDefaultRoute("192.0.2.1")))

        let otherPPP = try Scene()
        otherPPP.network.currentDefaultRoute = DefaultRoute(gateway: nil, interface: "ppp1")
        otherPPP.cleanup.run(otherPPP.state)
        #expect(!otherPPP.network.calls.contains(.replaceDefaultRoute("192.0.2.1")))

        var noGateway = try Scene()
        noGateway.state.gateway = nil
        noGateway.cleanup.run(noGateway.state)
        #expect(!noGateway.network.calls.contains { if case .replaceDefaultRoute = $0 { return true } else { return false } })
    }

    @Test func testAFailingStepDoesNotSkipTheRest() throws {
        let scene = try Scene()
        for name in ["replaceDefaultRoute", "deleteHostRoute", "removeDNS", "flushDNSCache"] { scene.network.fail(name) }
        scene.cleanup.run(scene.state)
        #expect(scene.network.calls.dropFirst() == [.replaceDefaultRoute("192.0.2.1"), .deleteHostRoute("198.51.100.7"), .removeDNS, .flushDNSCache])
        #expect(!scene.processes.isAlive(scene.pppd.pid))
    }

    @Test func testRunningTwiceIsHarmless() throws {
        let scene = try Scene()
        scene.cleanup.run(scene.state)
        let signals = scene.processes.signals
        let calls = scene.network.calls.count
        scene.cleanup.run(scene.state)
        #expect(scene.processes.signals == signals, "nothing is signalled again")
        #expect(scene.network.calls.dropFirst(calls) == [.deleteHostRoute("198.51.100.7"), .removeDNS, .flushDNSCache])
    }

    @Test func testDNSCacheIsFlushedOnlyIfDNSWasSetOrFound() throws {
        let processes = FakeProcessTable()
        let network = FakeNetwork()
        let cleanup = TunnelCleanup(processes: processes, network: network, grace: 0.05)
        let state = TunnelState(sessionID: TunnelStateTests.sessionID, serverIP: nil, gateway: nil)
        cleanup.run(state)
        #expect(network.calls == [.removeDNS])
        // A key left by a helper that crashed before recording dnsApplied is removed and flushed.
        try network.setDNS(DNSConfiguration(servers: ["192.0.2.53"], domains: []))
        cleanup.run(state)
        #expect(network.calls.suffix(2) == [.removeDNS, .flushDNSCache])
    }
}
