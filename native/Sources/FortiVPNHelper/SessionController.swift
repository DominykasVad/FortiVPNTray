import Foundation
import FortiVPNShared
import os

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
    /// Returns the child's identity, or nil if it had already exited.
    func start(_ request: ConnectRequest, sessionID: String, onEvent: @escaping @Sendable (TunnelEvent) -> Void) throws -> ProcessIdentity?
    /// Ends the child started for `sessionID`, if it is still running, and returns when it is gone.
    func stop(sessionID: String)
}

/// The helper's single session. Shared by every accepted connection, so one
/// session runs at a time whoever asks. XPC calls arrive on several queues;
/// all state is behind `lock`, and the launcher is only called outside it.
///
/// States and transitions (the public state in brackets):
///
///     idle ──connect──▶ preparing                      [connecting]   sweep, read gateway/DNS, save state
///     preparing ──▶ starting                           [connecting]   start() running, child not yet recorded
///     preparing+stop ──▶ idle                                         nothing was started
///     starting ──start returns──▶ running              [connecting]   connect replies with the session id
///     starting ──start throws──▶ idle                                 connect replies with the error
///     starting ──disconnect──▶ starting+stop           [disconnecting] disconnect replies at once; no stop yet
///     starting+stop ──start returns──▶ cleanup ──▶ idle               connect replies "disconnected"
///     starting+stop ──start throws──▶ idle                            nothing was started
///     starting ──child exits──▶ starting+exited        [connecting]   remembered until start returns
///     starting+exited ──start returns──▶ cleanup ──▶ idle             connect replies with the exit
///     running ──tunnel up──▶ running+up                [connected]    DNS applied
///     running ──disconnect──▶ cleanup ──▶ idle         [disconnecting]
///     running ──child exits──▶ cleanup ──▶ idle        [disconnecting] lastError says how it ended
///     starting+stop / cleanup ──disconnect──▶ (no change)
///     idle ──disconnect──▶ (no change)
///
/// `stop()` is never called while `start()` is running: a disconnect during
/// `start()` is recorded and acted on when `start()` returns, at which point
/// the launcher has recorded the child. So a child spawned before its PID was
/// recorded is still stopped, and never left running.
///
/// Every way a started session ends goes through `TunnelCleanup` (PLAN.md 2.5),
/// and the session slot is only freed once it is done. Sweeps, DNS changes and
/// cleanups hold `systemLock`, so they never overlap; `systemLock` is always
/// taken before `lock`, never while holding it. The state file mirrors the
/// session's `TunnelState` and is removed once its cleanup ran.
///
/// The log belongs to the session id, not to the state above: output that
/// arrives after the session ended (the child's last lines can come after its
/// exit) is still kept, until the next `connect` replaces the log.
final class SessionController: @unchecked Sendable {
    // @unchecked Sendable: `session`, `lastError` and `log` are only touched while holding `lock`.
    struct Refusal: Error, Equatable, CustomStringConvertible {
        let description: String
    }

    static let disconnectedWhileStarting = "Disconnected before the tunnel came up."

    private struct Session {
        let id: String
        let since: Date
        /// The SAML start URL openfortivpn will print for this request.
        let samlStartURL: String
        /// Set once the child printed `samlStartURL`.
        var samlURLPrinted = false
        var startReturned = false
        /// A disconnect was asked for, or the session is ending: nothing new is applied.
        var stopRequested = false
        var tunnelUp = false
        var exit: ChildExit?
        var parser = LogParser()
        /// System resolvers read before connecting, used if the tunnel brings none.
        var fallbackDNS: [String] = []
        var state: TunnelState
    }

    private let launcher: any TunnelLauncher
    private let cleanup: TunnelCleanup
    private let store: StateStore
    private let now: @Sendable () -> Date
    private let lock = NSLock()
    private let systemLock = NSLock()
    private let logger = Logger(subsystem: AppIdentity.helperLabel, category: "session")
    private var session: Session?
    private var lastError: String?
    /// The current or last session's output.
    private var log: SessionLog?

    init(launcher: any TunnelLauncher, cleanup: TunnelCleanup, store: StateStore, now: @escaping @Sendable () -> Date = Date.init) {
        self.launcher = launcher
        self.cleanup = cleanup
        self.store = store
        self.now = now
    }

    func connect(_ request: ConnectRequest) throws -> String {
        let id = UUID().uuidString
        try locked {
            guard session == nil else { throw Refusal(description: "A session is already active.") }
            session = Session(id: id, since: now(), samlStartURL: Self.samlStartURL(for: request),
                              state: TunnelState(sessionID: id, serverIP: nil, gateway: nil))
            log = SessionLog(sessionID: id)
            lastError = nil
        }
        do {
            try prepare(request, sessionID: id)
        } catch {
            locked {
                session = nil
                lastError = String(describing: error)
            }
            throw Refusal(description: String(describing: error))
        }
        guard locked({ session?.stopRequested == false }) else {
            store.clear()
            locked { session = nil }
            throw Refusal(description: Self.disconnectedWhileStarting)
        }

        let identity: ProcessIdentity?
        do {
            identity = try launcher.start(request, sessionID: id) { [weak self] event in self?.handle(event, sessionID: id) }
        } catch {
            store.clear()
            locked {
                session = nil
                lastError = String(describing: error)
            }
            throw Refusal(description: String(describing: error))
        }
        enum Next { case running, stop, exited(ChildExit) }
        let next: Next = locked {
            session?.startReturned = true
            session?.state.openfortivpn = identity
            if let state = session?.state { save(state) }
            if session?.stopRequested == true { return .stop }
            if let exit = session?.exit {
                session?.stopRequested = true
                return .exited(exit)
            }
            return .running
        }
        switch next {
        case .running:
            return id
        case .stop:
            end(sessionID: id, error: nil, stopChild: true)
            throw Refusal(description: Self.disconnectedWhileStarting)
        case .exited(let exit):
            end(sessionID: id, error: exit.description, stopChild: false)
            throw Refusal(description: exit.description)
        }
    }

    /// While `start()` is still running the stop is deferred to `connect`; otherwise
    /// replies once the session is cleaned up.
    func disconnect() {
        enum Action { case nothing, deferred, stop(String) }
        let action: Action = locked {
            guard let current = session, !current.stopRequested else { return .nothing }
            session?.stopRequested = true
            return current.startReturned ? .stop(current.id) : .deferred
        }
        guard case .stop(let id) = action else { return }
        end(sessionID: id, error: nil, stopChild: true)
    }

    /// Undoes a session the helper no longer runs, from the state file alone: at
    /// helper start and before each connect. A state file that cannot be read or is
    /// invalid is logged and left alone; nothing is undone on its say-so.
    func sweep() {
        systemLock.withLock { sweepLocked() }
    }

    func status() -> HelperStatus {
        locked {
            guard let session else { return HelperStatus(lastError: lastError) }
            let state: HelperStatus.State = session.stopRequested ? .disconnecting : session.tunnelUp ? .connected : .connecting
            return HelperStatus(state: state, sessionID: session.id,
                                interface: session.tunnelUp ? session.state.interface : nil,
                                vpnIP: session.tunnelUp ? session.parser.localIP : nil, since: session.since)
        }
    }

    /// Redacted log lines for the current or last session.
    func readLog(sessionID: String, offset: Int) throws -> LogChunk {
        guard offset >= 0 else { throw Refusal(description: "The log offset must not be negative.") }
        return try locked {
            guard let log, log.sessionID == sessionID else { throw Refusal(description: "Unknown session.") }
            return log.read(from: offset)
        }
    }

    /// The URL the user must open to log in: from when the child printed it until the
    /// tunnel is up or a disconnect was requested.
    ///
    /// It is built from the validated request, never taken from the child's output:
    /// the output only says when openfortivpn printed exactly this URL.
    func pendingSAMLURL() -> URL? {
        locked {
            guard let session, session.samlURLPrinted, !session.tunnelUp, !session.stopRequested else { return nil }
            return URL(string: session.samlStartURL)
        }
    }

    /// What openfortivpn prints for `saml-login` (`http_server.c`, `print_url`):
    /// `https://<host>:<port>/remote/saml/start?redirect=1` and `&realm=<url-encoded realm>`.
    /// A valid realm has only characters that url_encode keeps.
    static func samlStartURL(for request: ConnectRequest) -> String {
        "https://\(request.host):\(request.port)/remote/saml/start?redirect=1" + (request.realm.map { "&realm=" + $0 } ?? "")
    }

    /// `INFO:   Interface ppp0 is UP.` (`tunnel.c`, `on_ppp_if_up`), printed just before the tunnel is up.
    static func interface(in line: String) -> String? {
        guard let name = LogParser.capture(#"^INFO:\s+Interface (\S+) is UP\.$"#, line), TunnelState.isPPPInterface(name) else { return nil }
        return name
    }

    // MARK: Private

    /// Sweeps what an earlier helper left, records what cleanup will need, and saves it
    /// before anything is started.
    private func prepare(_ request: ConnectRequest, sessionID: String) throws {
        try systemLock.withLock {
            sweepLocked()
            let network = cleanup.network
            let state = TunnelState(sessionID: sessionID, serverIP: network.resolveIPv4(request.host), gateway: network.defaultRoute()?.gateway)
            let fallback = request.useSystemDNSFallback ? network.systemDNSServers() : []
            do { try store.save(state) } catch {
                throw Refusal(description: "Cannot save the session state: \(error)")
            }
            locked {
                session?.state = state
                session?.fallbackDNS = fallback
            }
        }
    }

    private func sweepLocked() {
        let state: TunnelState?
        do {
            state = try store.load()
        } catch {
            logger.error("Ignoring the state file: \(String(describing: error), privacy: .public)")
            return
        }
        guard let state else { return }
        logger.notice("Cleaning up after an earlier session")
        cleanup.run(state)
        store.clear()
    }

    /// Cleans up the session and frees its slot. The caller has set `stopRequested`.
    /// `stopChild` asks the launcher to stop the child; after the child exited there is
    /// nothing for it to do, and cleanup's identity check covers it either way.
    private func end(sessionID: String, error: String?, stopChild: Bool) {
        systemLock.withLock {
            if let state = locked({ session?.id == sessionID ? session?.state : nil }) {
                cleanup.run(state) { if stopChild { launcher.stop(sessionID: sessionID) } }
                store.clear()
            }
        }
        locked {
            guard session?.id == sessionID else { return }
            session = nil
            if let error { lastError = error }
        }
    }

    private func applyDNS(_ configuration: DNSConfiguration, sessionID: String) {
        systemLock.withLock {
            guard locked({ session?.id == sessionID && session?.stopRequested == false }) else { return }
            do {
                try cleanup.network.setDNS(configuration)
            } catch {
                logger.error("Cannot apply the tunnel's DNS: \(String(describing: error), privacy: .public)")
                return
            }
            locked {
                guard session?.id == sessionID else { return }
                session?.state.dnsApplied = true
                if let state = session?.state { save(state) }
            }
        }
    }

    private func handle(_ event: TunnelEvent, sessionID: String) {
        enum After { case nothing, applyDNS(DNSConfiguration), end(String) }
        let after: After = locked {
            if case .output(let line) = event, log?.sessionID == sessionID {
                log?.append(rawLine: line)
            }
            guard let current = session, current.id == sessionID else { return .nothing }
            switch event {
            case .output(let line):
                guard !current.stopRequested else { return .nothing }
                if line == "INFO:   Authenticate at '\(current.samlStartURL)'" { session?.samlURLPrinted = true }
                _ = session?.parser.consume(line)
                if let interface = Self.interface(in: line) { record { $0.interface = interface } }
                recordPPPD()
            case .tunnelUp:
                guard !current.stopRequested else { return .nothing }
                session?.tunnelUp = true
                recordPPPD()
                guard let parser = session?.parser,
                      let dns = try? DNSConfiguration(servers: parser.effectiveDNS(fallback: current.fallbackDNS), domains: parser.dnsSuffixes)
                else { return .nothing }
                return .applyDNS(dns)
            case .exited(let exit):
                if current.stopRequested {
                    break   // The cleanup in progress ends the session.
                } else if !current.startReturned {
                    session?.exit = exit
                } else {
                    session?.stopRequested = true
                    return .end(exit.description)
                }
            }
            return .nothing
        }
        switch after {
        case .nothing: break
        case .applyDNS(let dns): applyDNS(dns, sessionID: sessionID)
        case .end(let error): end(sessionID: sessionID, error: error, stopChild: false)
        }
    }

    /// Records pppd while openfortivpn still runs (PLAN.md 2.5). Called holding `lock`.
    private func recordPPPD() {
        guard let state = session?.state, state.pppd == nil, let openfortivpn = state.openfortivpn,
              let pppd = cleanup.findPPPD(of: openfortivpn) else { return }
        record { $0.pppd = pppd }
    }

    /// Changes the session's state and saves it. Called holding `lock`.
    private func record(_ change: (inout TunnelState) -> Void) {
        guard var state = session?.state else { return }
        change(&state)
        guard state != session?.state else { return }
        session?.state = state
        save(state)
    }

    private func save(_ state: TunnelState) {
        do { try store.save(state) } catch {
            logger.error("Cannot save the session state: \(String(describing: error), privacy: .public)")
        }
    }

    private func locked<Value>(_ body: () throws -> Value) rethrows -> Value {
        lock.lock()
        defer { lock.unlock() }
        return try body()
    }
}
