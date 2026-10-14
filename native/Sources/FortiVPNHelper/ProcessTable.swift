import Darwin
import Foundation

/// A PID together with what makes it that process and not a later one with the
/// same number: its start time and executable (PLAN.md 2.5).
struct ProcessIdentity: Codable, Equatable, Sendable {
    let pid: Int32
    let startSeconds: UInt64
    let startMicroseconds: UInt64
    let executable: String

    var isValid: Bool {
        pid > 1 && startMicroseconds < 1_000_000 && executable.hasPrefix("/")
            && executable.utf8.count < Int(MAXPATHLEN) && !executable.utf8.contains(0)
    }
}

/// The calls the helper makes on other processes. Behind a protocol so tests can fake them.
protocol ProcessTable: Sendable {
    /// The identity of `pid` now, or nil if there is no such process or it is a zombie.
    func identity(of pid: pid_t) -> ProcessIdentity?
    /// The PIDs whose parent is `pid`.
    func children(of pid: pid_t) -> [pid_t]
    /// Sends `signal` to `pid` without any check. Only `signal(_:ifStill:)` calls it.
    func send(_ signal: Int32, to pid: pid_t)
}

extension ProcessTable {
    /// Whether `recorded` is still running as the same process.
    func isRunning(_ recorded: ProcessIdentity) -> Bool {
        identity(of: recorded.pid) == recorded
    }

    /// Signals `recorded.pid` only while it is still the recorded process. Returns
    /// whether the signal was sent. A process that exited, or a PID now used by
    /// another process, is never signalled.
    ///
    /// The process can still exit and its PID be reused between the check and
    /// `kill`; no macOS API closes that window for a process that is not our child.
    @discardableResult
    func signal(_ signal: Int32, ifStill recorded: ProcessIdentity) -> Bool {
        guard isRunning(recorded) else { return false }
        send(signal, to: recorded.pid)
        return true
    }

    /// `first`, then SIGKILL if it is still running after `grace`; returns when it
    /// is gone or `grace` after SIGKILL.
    func stop(_ recorded: ProcessIdentity, first: Int32, grace: TimeInterval) {
        for signal in [first, SIGKILL] {
            guard self.signal(signal, ifStill: recorded) else { return }
            let deadline = Date().addingTimeInterval(grace)
            while isRunning(recorded) && Date() < deadline { usleep(20_000) }
        }
    }
}

/// The real process table: `proc_pidinfo`, `proc_pidpath`, `proc_listchildpids`, `kill`.
struct SystemProcessTable: ProcessTable {
    func identity(of pid: pid_t) -> ProcessIdentity? {
        guard pid > 0 else { return nil }
        var info = proc_bsdinfo()
        let size = Int32(MemoryLayout<proc_bsdinfo>.size)
        guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, size) == size, info.pbi_pid == UInt32(pid),
              info.pbi_status != UInt32(SZOMB) else { return nil }
        var path = [CChar](repeating: 0, count: Int(MAXPATHLEN))
        guard proc_pidpath(pid, &path, UInt32(path.count)) > 0 else { return nil }
        let identity = ProcessIdentity(pid: pid, startSeconds: info.pbi_start_tvsec, startMicroseconds: info.pbi_start_tvusec,
                                       executable: String(decoding: path.prefix(while: { $0 != 0 }).map(UInt8.init(bitPattern:)), as: UTF8.self))
        // Read again: if the process exited and the PID was reused in between, the start time differs.
        var again = proc_bsdinfo()
        guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &again, size) == size,
              again.pbi_start_tvsec == info.pbi_start_tvsec, again.pbi_start_tvusec == info.pbi_start_tvusec else { return nil }
        return identity
    }

    func children(of pid: pid_t) -> [pid_t] {
        guard pid > 0 else { return [] }
        var buffer = [pid_t](repeating: 0, count: 256)
        let count = proc_listchildpids(pid, &buffer, Int32(buffer.count * MemoryLayout<pid_t>.size))
        guard count > 0 else { return [] }
        return Array(buffer.prefix(Int(count))).filter { $0 > 0 }
    }

    func send(_ signal: Int32, to pid: pid_t) {
        guard pid > 1 else { return }
        kill(pid, signal)
    }
}
