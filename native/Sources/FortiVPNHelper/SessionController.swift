import Foundation
import FortiVPNShared

/// Starts and stops the openfortivpn child for a session. Task 2.3 adds the real one.
protocol TunnelLauncher: Sendable {
    func start(_ request: ConnectRequest, sessionID: String) throws
    func stop()
}

/// The launcher until task 2.3: refuses every start.
struct UnavailableLauncher: TunnelLauncher {
    struct Unavailable: Error, CustomStringConvertible {
        var description: String { "This helper build cannot start a tunnel yet." }
    }

    func start(_ request: ConnectRequest, sessionID: String) throws { throw Unavailable() }
    func stop() {}
}

/// The helper's single session. Shared by every accepted connection, so one
/// session runs at a time whoever asks. XPC calls arrive on several queues;
/// all state is behind `lock`.
final class SessionController: @unchecked Sendable {
    // @unchecked Sendable: `current` and `lastSessionID` are only touched while holding `lock`.
    struct Refusal: Error, Equatable, CustomStringConvertible {
        let description: String
    }

    private let launcher: any TunnelLauncher
    private let now: @Sendable () -> Date
    private let lock = NSLock()
    private var current = HelperStatus()
    private var lastSessionID: String?

    init(launcher: any TunnelLauncher, now: @escaping @Sendable () -> Date = Date.init) {
        self.launcher = launcher
        self.now = now
    }

    /// Claims the session slot, then starts the tunnel outside the lock.
    func connect(_ request: ConnectRequest) throws -> String {
        let sessionID = UUID().uuidString
        try locked {
            guard current.state == .idle else { throw Refusal(description: "A session is already active.") }
            current = HelperStatus(state: .connecting, sessionID: sessionID, since: now())
            lastSessionID = sessionID
        }
        do {
            try launcher.start(request, sessionID: sessionID)
        } catch {
            locked { current = HelperStatus(lastError: String(describing: error)) }
            throw Refusal(description: String(describing: error))
        }
        return sessionID
    }

    /// Stopping when nothing runs is not an error.
    func disconnect() {
        let wasActive = locked {
            guard current.state != .idle else { return false }
            current.state = .disconnecting
            return true
        }
        guard wasActive else { return }
        launcher.stop()
        locked { current = HelperStatus() }
    }

    func status() -> HelperStatus { locked { current } }

    /// Log lines for the current or last session. Task 2.4 fills in the lines.
    func readLog(sessionID: String, offset: Int) throws -> LogChunk {
        guard offset >= 0 else { throw Refusal(description: "The log offset must not be negative.") }
        guard locked({ lastSessionID }) == sessionID else { throw Refusal(description: "Unknown session.") }
        return LogChunk(lines: [], nextOffset: offset)
    }

    /// Task 2.4 parses the URL from the child's output.
    func pendingSAMLURL() -> URL? { nil }

    private func locked<Value>(_ body: () throws -> Value) rethrows -> Value {
        lock.lock()
        defer { lock.unlock() }
        return try body()
    }
}
