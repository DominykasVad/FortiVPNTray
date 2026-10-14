import Foundation
import FortiVPNShared

/// Starts the root-owned openfortivpn copy for one session (PLAN.md 2.3).
///
/// Before each spawn the whole install is verified; the config file is written
/// to the run directory; the child gets a fixed argv and environment. The config
/// file is deleted once the tunnel is up and when the child exits.
///
/// `SessionController` never calls `start` and `stop` concurrently, and calls
/// `stop` only after `start` has returned, so the child is always recorded here
/// before anyone tries to stop it.
final class OpenFortiVPNLauncher: TunnelLauncher, @unchecked Sendable {
    // @unchecked Sendable: `child` is only touched while holding `lock`.
    struct Failure: Error, Equatable, CustomStringConvertible {
        let description: String
    }

    private struct Child {
        let sessionID: String
        let process: Process
        let configName: String
        /// Nil if the child had already exited when it was recorded.
        let identity: ProcessIdentity?
    }

    /// openfortivpn's log line once the tunnel is up (`tunnel.c`).
    static let tunnelUpMarker = "Tunnel is up and running"
    /// How long `stop` waits after SIGINT before SIGKILL, and after SIGKILL.
    static let stopGrace: TimeInterval = 2

    let install: OpenFortiVPNInstall
    let runDirectory: RunDirectory
    let processes: any ProcessTable
    /// Test hook: called after the child is spawned and before it is recorded.
    private let spawned: (@Sendable (pid_t) -> Void)?
    private let lock = NSLock()
    private var child: Child?

    init(install: OpenFortiVPNInstall = .production, runDirectory: RunDirectory = .production,
         processes: any ProcessTable = SystemProcessTable(), spawned: (@Sendable (pid_t) -> Void)? = nil) {
        self.install = install
        self.runDirectory = runDirectory
        self.processes = processes
        self.spawned = spawned
    }

    /// Exactly `-c <file> -v`: everything else is in the config file (decision log, 1.3).
    static func arguments(configPath: String) -> [String] { ["-c", configPath, "-v"] }

    /// The child's entire environment. OpenSSL's compiled-in paths under
    /// `/opt/homebrew` are user-writable, so every one of them is overridden (S2, 2.3).
    static func environment(for install: OpenFortiVPNInstall) -> [String: String] {
        [
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "OPENSSL_CONF": "/dev/null",
            "OPENSSL_MODULES": install.modulesDirectory,
            "SSL_CERT_FILE": "/etc/ssl/cert.pem",
            "SSL_CERT_DIR": install.certsDirectory,
        ]
    }

    @discardableResult
    func start(_ request: ConnectRequest, sessionID: String, onEvent: @escaping @Sendable (TunnelEvent) -> Void) throws -> ProcessIdentity? {
        guard locked({ child == nil }) else { throw Failure(description: "openfortivpn is already running.") }
        guard UUID(uuidString: sessionID) != nil else { throw Failure(description: "Bad session id.") }
        try install.verify()
        let config = try OpenFortiVPNConfig.render(request)
        try runDirectory.prepare()
        let configName = sessionID + ".conf"
        let configPath = try runDirectory.create(configName, contents: Data(config.utf8))

        let process = Process()
        process.executableURL = URL(fileURLWithPath: install.binary)
        process.arguments = Self.arguments(configPath: configPath)
        process.environment = Self.environment(for: install)
        process.currentDirectoryURL = URL(fileURLWithPath: "/")
        process.standardInput = FileHandle.nullDevice
        let output = Pipe()
        process.standardOutput = output
        process.standardError = output

        let runDirectory = runDirectory
        let lines = LineSplitter { line in
            if line.contains(Self.tunnelUpMarker) {
                runDirectory.remove(configName)
                onEvent(.output(line))
                onEvent(.tunnelUp)
            } else {
                onEvent(.output(line))
            }
        }
        output.fileHandleForReading.readabilityHandler = { handle in
            let data = handle.availableData
            if data.isEmpty {
                handle.readabilityHandler = nil
                lines.finish()
            } else {
                lines.append(data)
            }
        }
        process.terminationHandler = { [weak self] process in
            runDirectory.remove(configName)
            self?.forget(process)
            onEvent(.exited(process.terminationReason == .uncaughtSignal ? .signal(process.terminationStatus) : .status(process.terminationStatus)))
        }
        do {
            try process.run()
        } catch {
            output.fileHandleForReading.readabilityHandler = nil
            runDirectory.remove(configName)
            throw Failure(description: "Cannot start openfortivpn: \(error.localizedDescription)")
        }
        spawned?(process.processIdentifier)
        // posix_spawn has returned, so the child already runs the binary: this is its identity.
        let identity = processes.identity(of: process.processIdentifier)
        locked { child = Child(sessionID: sessionID, process: process, configName: configName, identity: identity) }
        // A child that already exited may have been reaped before it was recorded; its
        // termination handler then found nothing to forget.
        if !process.isRunning { forget(process) }
        return identity
    }

    /// SIGINT to the recorded child, SIGKILL if it is still running after `stopGrace`.
    /// Only the process this launcher started is signalled, and only while it is still
    /// that process (same start time and executable, PLAN.md 2.5).
    ///
    /// Known, accepted limit of Foundation's Process: the child can exit and be reaped
    /// between the identity check and kill(), and its PID could in theory be reused by
    /// then. Process offers no way to signal it that excludes this (no pidfd on macOS,
    /// and Process reaps the child itself), so the window stays this short.
    func stop(sessionID: String) {
        guard let child = locked({ child }), child.sessionID == sessionID else { return }
        if let identity = child.identity {
            processes.stop(identity, first: SIGINT, grace: Self.stopGrace)
        }
        // A dead child is a zombie until Process reaps it; return only once it is reaped,
        // so "stopped" means its PID is gone.
        let deadline = Date().addingTimeInterval(Self.stopGrace)
        while child.process.isRunning && Date() < deadline { usleep(20_000) }
        runDirectory.remove(child.configName)
        forget(child.process)
    }

    private func forget(_ process: Process) {
        locked { if child?.process === process { child = nil } }
    }

    private func locked<Value>(_ body: () throws -> Value) rethrows -> Value {
        lock.lock()
        defer { lock.unlock() }
        return try body()
    }
}

/// Splits the child's output into lines. Overlong lines are cut, so a child
/// cannot make the helper buffer without limit.
final class LineSplitter: @unchecked Sendable {
    // @unchecked Sendable: `buffer` is only touched while holding `lock`.
    static let maxLineLength = 8192
    private let lock = NSLock()
    private var buffer = Data()
    private let onLine: @Sendable (String) -> Void

    init(onLine: @escaping @Sendable (String) -> Void) {
        self.onLine = onLine
    }

    func append(_ data: Data) {
        var lines: [String] = []
        lock.lock()
        buffer.append(data)
        while let newline = buffer.firstIndex(of: UInt8(ascii: "\n")) {
            lines.append(Self.text(buffer[buffer.startIndex..<newline]))
            buffer.removeSubrange(buffer.startIndex...newline)
        }
        if buffer.count > Self.maxLineLength {
            lines.append(Self.text(buffer))
            buffer.removeAll()
        }
        lock.unlock()
        lines.forEach(onLine)
    }

    func finish() {
        lock.lock()
        let rest = buffer
        buffer.removeAll()
        lock.unlock()
        if !rest.isEmpty { onLine(Self.text(rest)) }
    }

    private static func text(_ bytes: Data) -> String {
        String(decoding: bytes.prefix(maxLineLength), as: UTF8.self)
    }
}
