import Foundation
import FortiVPNShared
@testable import FortiVPNHelper

/// An imaginary process table. A process exits on any signal unless told to
/// ignore it; signals sent are recorded.
final class FakeProcessTable: ProcessTable, @unchecked Sendable {
    // @unchecked Sendable: all fields are only touched while holding `lock`.
    private let lock = NSLock()
    private var running: [pid_t: ProcessIdentity] = [:]
    private var parents: [pid_t: pid_t] = [:]
    private var ignored: [pid_t: Set<Int32>] = [:]
    private var _signals: [Signal] = []
    private var nextPID: pid_t = 40_000

    struct Signal: Equatable { let pid: pid_t; let signal: Int32 }

    var signals: [Signal] { lock.withLock { _signals } }

    /// Starts an imaginary process and returns its identity.
    @discardableResult
    func spawn(_ executable: String, parent: pid_t? = nil, ignoring: Set<Int32> = []) -> ProcessIdentity {
        lock.withLock {
            nextPID += 1
            let identity = ProcessIdentity(pid: nextPID, startSeconds: 1_700_000_000 + UInt64(nextPID), startMicroseconds: 250_000, executable: executable)
            running[nextPID] = identity
            parents[nextPID] = parent
            ignored[nextPID] = ignoring
            return identity
        }
    }

    /// The process exits by itself; its children are reparented to launchd.
    func exit(_ pid: pid_t) {
        lock.withLock {
            running[pid] = nil
            for (child, parent) in parents where parent == pid { parents[child] = 1 }
        }
    }

    /// Another process now has `pid`.
    func reuse(_ pid: pid_t, executable: String) {
        lock.withLock {
            running[pid] = ProcessIdentity(pid: pid, startSeconds: 1_800_000_000, startMicroseconds: 0, executable: executable)
            parents[pid] = 1
            ignored[pid] = []
        }
    }

    func isAlive(_ pid: pid_t) -> Bool { lock.withLock { running[pid] != nil } }

    func identity(of pid: pid_t) -> ProcessIdentity? { lock.withLock { running[pid] } }

    func children(of pid: pid_t) -> [pid_t] {
        lock.withLock { parents.filter { $0.value == pid && running[$0.key] != nil }.map(\.key).sorted() }
    }

    func send(_ signal: Int32, to pid: pid_t) {
        let exited: Bool = lock.withLock {
            _signals.append(Signal(pid: pid, signal: signal))
            return running[pid] != nil && !(ignored[pid] ?? []).contains(signal)
        }
        if exited { exit(pid) }
    }
}

/// Routes and DNS that exist only in memory; every call is recorded in order.
final class FakeNetwork: NetworkControl, @unchecked Sendable {
    // @unchecked Sendable: all fields are only touched while holding `lock`.
    enum Call: Equatable {
        case deleteHostRoute(String), replaceDefaultRoute(String), setDNS(DNSConfiguration), removeDNS, flushDNSCache
    }

    private let lock = NSLock()
    private var _calls: [Call] = []
    private var _defaultRoute: DefaultRoute?
    private var _dns: DNSConfiguration?
    private var _failing: Set<String> = []
    let addresses: [String: String]
    let systemResolvers: [String]

    init(defaultRoute: DefaultRoute? = DefaultRoute(gateway: "192.0.2.1", interface: "en0"),
         addresses: [String: String] = ["vpn.example.com": "198.51.100.7"], systemResolvers: [String] = ["192.0.2.53"]) {
        _defaultRoute = defaultRoute
        self.addresses = addresses
        self.systemResolvers = systemResolvers
    }

    var calls: [Call] { lock.withLock { _calls } }
    var dns: DNSConfiguration? { lock.withLock { _dns } }
    var currentDefaultRoute: DefaultRoute? {
        get { lock.withLock { _defaultRoute } }
        set { lock.withLock { _defaultRoute = newValue } }
    }

    /// Makes the named operation (`deleteHostRoute`, `replaceDefaultRoute`, `setDNS`, `removeDNS`, `flushDNSCache`) throw.
    func fail(_ name: String) { lock.withLock { _ = _failing.insert(name) } }

    private func record(_ call: Call, _ name: String) throws {
        let fails = lock.withLock { () -> Bool in
            _calls.append(call)
            return _failing.contains(name)
        }
        if fails { throw NetworkFailure(description: "\(name) failed") }
    }

    func defaultRoute() -> DefaultRoute? { currentDefaultRoute }
    func resolveIPv4(_ host: String) -> String? { addresses[host] ?? (Validation.ipv4(host) ? host : nil) }
    func systemDNSServers() -> [String] { systemResolvers }

    func deleteHostRoute(_ address: String) throws { try record(.deleteHostRoute(address), "deleteHostRoute") }

    func replaceDefaultRoute(gateway: String) throws {
        try record(.replaceDefaultRoute(gateway), "replaceDefaultRoute")
        currentDefaultRoute = DefaultRoute(gateway: gateway, interface: "en0")
    }

    func setDNS(_ configuration: DNSConfiguration) throws {
        try record(.setDNS(configuration), "setDNS")
        lock.withLock { _dns = configuration }
    }

    func removeDNS() throws -> Bool {
        try record(.removeDNS, "removeDNS")
        return lock.withLock {
            defer { _dns = nil }
            return _dns != nil
        }
    }

    func flushDNSCache() throws { try record(.flushDNSCache, "flushDNSCache") }
}

/// One directory for this test process's state stores, removed when the process exits.
/// (A store must not disappear while a controller that only holds its path still runs.)
enum TestDirectories {
    static let root: String = {
        let temporary = FileManager.default.temporaryDirectory.appendingPathComponent("fvt-state-\(getpid())-" + UUID().uuidString)
        try! FileManager.default.createDirectory(at: temporary, withIntermediateDirectories: false)
        let path = try! FakeInstall.realPath(temporary.path)
        chmod(path, 0o755)
        atexit { try? FileManager.default.removeItem(atPath: TestDirectories.root) }
        return path
    }()
}

/// A state store in a temporary directory, trusted as if the test user were root.
struct TemporaryStateStore {
    let root: String
    let store: StateStore

    init() throws {
        root = TestDirectories.root + "/" + UUID().uuidString
        try FakeInstall.makeDirectory(root)
        store = StateStore(directory: RunDirectory(path: root + "/support", trust: FakeInstall.trust, owner: getuid()))
    }

    var exists: Bool { FileManager.default.fileExists(atPath: store.path) }
}

extension SessionController {
    /// For tests that do not look at the system side: fake processes (the mock
    /// launcher's, if it is one) and network, and a temporary state store.
    convenience init(launcher: any TunnelLauncher, now: @escaping @Sendable () -> Date = Date.init) {
        let processes = (launcher as? MockLauncher)?.processes ?? FakeProcessTable()
        self.init(launcher: launcher, cleanup: TunnelCleanup(processes: processes, network: FakeNetwork(), grace: 0.05),
                  store: try! TemporaryStateStore().store, now: now)
    }
}

/// A `SessionController` over a mock launcher, fake processes and network, and a temporary state store.
struct Harness {
    let launcher: MockLauncher
    let processes: FakeProcessTable
    let network: FakeNetwork
    let state: TemporaryStateStore
    let sessions: SessionController

    init(launcher: MockLauncher? = nil, network: FakeNetwork = FakeNetwork(), now: @escaping @Sendable () -> Date = Date.init) throws {
        let launcher = launcher ?? MockLauncher()
        self.launcher = launcher
        processes = launcher.processes
        self.network = network
        state = try TemporaryStateStore()
        sessions = SessionController(launcher: launcher, cleanup: TunnelCleanup(processes: processes, network: network, grace: 0.05),
                                     store: state.store, now: now)
    }

    func saved() throws -> TunnelState? { try state.store.load() }
}
