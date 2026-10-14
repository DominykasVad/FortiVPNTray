import Foundation
import FortiVPNShared

/// How the child ended.
enum ChildExit: Equatable, Sendable, CustomStringConvertible {
    case status(Int32)
    case signal(Int32)

    var description: String {
        switch self {
        case .status(let code): return "openfortivpn exited with status \(code)."
        case .signal(let number): return "openfortivpn was ended by signal \(number)."
        }
    }
}

/// What a launcher reports about its child, from any thread.
enum TunnelEvent: Equatable, Sendable {
    /// One line of the child's output, not yet redacted. Never logged as is.
    case output(String)
    case tunnelUp
    case exited(ChildExit)
}

/// Starts and stops the openfortivpn child for a session.
protocol TunnelLauncher: Sendable {
    /// Spawns the child and returns once it is recorded, so `stop` can reach it.
    func start(_ request: ConnectRequest, sessionID: String, onEvent: @escaping @Sendable (TunnelEvent) -> Void) throws
    /// Ends the child started for `sessionID`, if it is still running, and returns when it is gone.
    func stop(sessionID: String)
}

/// The helper's single session. Shared by every accepted connection, so one
/// session runs at a time whoever asks. XPC calls arrive on several queues;
/// all state is behind `lock`, and the launcher is only called outside it.
///
/// States and transitions (the public state in brackets):
///
///     idle ──connect──▶ starting                       [connecting]   start() running, child not yet recorded
///     starting ──start returns──▶ running              [connecting]   connect replies with the session id
///     starting ──start throws──▶ idle                                 connect replies with the error
///     starting ──disconnect──▶ starting+stop           [disconnecting] disconnect replies at once; no stop yet
///     starting+stop ──start returns──▶ stop() ──▶ idle                connect replies "disconnected"
///     starting+stop ──start throws──▶ idle                            nothing was started
///     starting ──child exits──▶ starting+exited        [connecting]   remembered until start returns
///     starting+exited ──start returns──▶ idle                         connect replies with the exit
///     running ──tunnel up──▶ running+up                [connected]
///     running ──disconnect──▶ stopping ──stop()──▶ idle [disconnecting]
///     running ──child exits──▶ idle                                   lastError says how it ended
///     starting+stop / stopping ──disconnect──▶ (no change)
///     idle ──disconnect──▶ (no change)
///
/// `stop()` is never called while `start()` is running: a disconnect during
/// `start()` is recorded and acted on when `start()` returns, at which point
/// the launcher has recorded the child. So a child spawned before its PID was
/// recorded is still stopped, and never left running.
final class SessionController: @unchecked Sendable {
    // @unchecked Sendable: `session`, `lastError` and `lastSessionID` are only touched while holding `lock`.
    struct Refusal: Error, Equatable, CustomStringConvertible {
        let description: String
    }

    static let disconnectedWhileStarting = "Disconnected before the tunnel came up."

    private struct Session {
        let id: String
        let since: Date
        var startReturned = false
        var stopRequested = false
        var tunnelUp = false
        var exit: ChildExit?
    }

    private let launcher: any TunnelLauncher
    private let now: @Sendable () -> Date
    private let lock = NSLock()
    private var session: Session?
    private var lastError: String?
    private var lastSessionID: String?

    init(launcher: any TunnelLauncher, now: @escaping @Sendable () -> Date = Date.init) {
        self.launcher = launcher
        self.now = now
    }

    func connect(_ request: ConnectRequest) throws -> String {
        let id = UUID().uuidString
        try locked {
            guard session == nil else { throw Refusal(description: "A session is already active.") }
            session = Session(id: id, since: now())
            lastSessionID = id
            lastError = nil
        }
        do {
            try launcher.start(request, sessionID: id) { [weak self] event in self?.handle(event, sessionID: id) }
        } catch {
            locked {
                session = nil
                lastError = String(describing: error)
            }
            throw Refusal(description: String(describing: error))
        }
        enum Next { case running, stop, exited(ChildExit) }
        let next: Next = locked {
            session?.startReturned = true
            if session?.stopRequested == true { return .stop }
            if let exit = session?.exit {
                session = nil
                lastError = exit.description
                return .exited(exit)
            }
            return .running
        }
        switch next {
        case .running:
            return id
        case .stop:
            launcher.stop(sessionID: id)
            locked { if session?.id == id { session = nil } }
            throw Refusal(description: Self.disconnectedWhileStarting)
        case .exited(let exit):
            throw Refusal(description: exit.description)
        }
    }

    /// Replies at once. While `start()` is still running the stop is deferred to `connect`.
    func disconnect() {
        enum Action { case nothing, deferred, stop(String) }
        let action: Action = locked {
            guard let current = session, !current.stopRequested else { return .nothing }
            session?.stopRequested = true
            return current.startReturned ? .stop(current.id) : .deferred
        }
        guard case .stop(let id) = action else { return }
        launcher.stop(sessionID: id)
        locked { if session?.id == id { session = nil } }
    }

    func status() -> HelperStatus {
        locked {
            guard let session else { return HelperStatus(lastError: lastError) }
            let state: HelperStatus.State = session.stopRequested ? .disconnecting : session.tunnelUp ? .connected : .connecting
            return HelperStatus(state: state, sessionID: session.id, since: session.since)
        }
    }

    /// Log lines for the current or last session. Task 2.4 fills in the lines.
    func readLog(sessionID: String, offset: Int) throws -> LogChunk {
        guard offset >= 0 else { throw Refusal(description: "The log offset must not be negative.") }
        guard locked({ lastSessionID }) == sessionID else { throw Refusal(description: "Unknown session.") }
        return LogChunk(lines: [], nextOffset: offset)
    }

    /// Task 2.4 parses the URL from the child's output.
    func pendingSAMLURL() -> URL? { nil }

    private func handle(_ event: TunnelEvent, sessionID: String) {
        locked {
            guard let current = session, current.id == sessionID else { return }
            switch event {
            case .output:
                break   // Task 2.4: redact and keep.
            case .tunnelUp:
                session?.tunnelUp = true
            case .exited(let exit):
                if current.stopRequested {
                    break   // The stop in progress ends the session.
                } else if !current.startReturned {
                    session?.exit = exit
                } else {
                    session = nil
                    lastError = exit.description
                }
            }
        }
    }

    private func locked<Value>(_ body: () throws -> Value) rethrows -> Value {
        lock.lock()
        defer { lock.unlock() }
        return try body()
    }
}
