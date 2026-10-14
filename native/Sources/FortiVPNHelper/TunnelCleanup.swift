import Foundation
import FortiVPNShared
import os

/// Undoes what a session did to the system (PLAN.md 2.5, F6–F8). Every step can
/// run any number of times, and runs whether or not the steps before it worked.
/// Nothing is signalled unless it is still the recorded process; nothing is
/// matched by name.
struct TunnelCleanup: Sendable {
    /// pppd as openfortivpn 1.24.1 runs it (`PPP_PATH`).
    static let pppdPath = "/usr/sbin/pppd"
    /// How long each stop waits after a signal before the next one.
    static let grace: TimeInterval = 2

    let processes: any ProcessTable
    let network: any NetworkControl
    let grace: TimeInterval
    private let log = Logger(subsystem: AppIdentity.helperLabel, category: "cleanup")

    init(processes: any ProcessTable, network: any NetworkControl, grace: TimeInterval = TunnelCleanup.grace) {
        self.processes = processes
        self.network = network
        self.grace = grace
    }

    /// The pppd child of `openfortivpn`, while `openfortivpn` is still the recorded
    /// process. Only a direct child running `pppdPath` counts.
    func findPPPD(of openfortivpn: ProcessIdentity) -> ProcessIdentity? {
        guard processes.isRunning(openfortivpn) else { return nil }
        let candidates = processes.children(of: openfortivpn.pid).compactMap(processes.identity(of:))
            .filter { $0.executable == Self.pppdPath }
        // If openfortivpn exited meanwhile, the children listed may belong to a reused PID.
        guard processes.isRunning(openfortivpn), candidates.count == 1 else { return nil }
        return candidates[0]
    }

    /// Runs every step for `state`. `stopChild` first ends the child through its
    /// launcher, if this helper started it; the recorded identity is stopped afterwards
    /// either way, which does nothing when it is already gone.
    func run(_ state: TunnelState, stopChild: () -> Void = {}) {
        // pppd must be found while openfortivpn still runs: once openfortivpn is gone,
        // its pppd is reparented to launchd and no longer its child.
        let pppd = state.pppd ?? state.openfortivpn.flatMap(findPPPD(of:))

        stopChild()
        if let openfortivpn = state.openfortivpn {
            processes.stop(openfortivpn, first: SIGINT, grace: grace)
        }

        // Only while our pppd is alive is the interface still ours; a ppp interface
        // with the same name afterwards belongs to someone else.
        if let pppd, let interface = state.interface, let gateway = state.gateway, processes.isRunning(pppd),
           network.defaultRoute()?.interface == interface {
            step("restore the default route") { try network.replaceDefaultRoute(gateway: gateway) }
        }
        if let pppd {
            processes.stop(pppd, first: SIGTERM, grace: grace)
        }
        if let serverIP = state.serverIP {
            step("remove the gateway host route") { try network.deleteHostRoute(serverIP) }
        }
        var removed = false
        step("remove the DNS configuration") { removed = try network.removeDNS() }
        if removed || state.dnsApplied {
            step("flush the DNS cache") { try network.flushDNSCache() }
        }
    }

    private func step(_ name: String, _ body: () throws -> Void) {
        do {
            try body()
        } catch {
            log.error("Cleanup could not \(name, privacy: .public): \(String(describing: error), privacy: .public)")
        }
    }
}
