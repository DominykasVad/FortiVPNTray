import Testing
import Foundation
@testable import FortiVPNHelper

/// Process identity (PLAN.md 2.5): nothing is signalled unless it is still the recorded process.
struct ProcessTableTests {
    private let table = SystemProcessTable()

    private func sleeper(_ seconds: String = "30") throws -> Process {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/sleep")
        process.arguments = [seconds]
        process.environment = [:]
        try process.run()
        return process
    }

    @Test func testIdentityOfARunningChild() throws {
        let child = try sleeper()
        defer { child.terminate(); child.waitUntilExit() }
        let identity = try #require(table.identity(of: child.processIdentifier))
        #expect(identity.pid == child.processIdentifier)
        #expect(identity.executable == "/bin/sleep")
        #expect(identity.startSeconds > 1_600_000_000 && identity.startMicroseconds < 1_000_000)
        #expect(identity.isValid)
        #expect(table.identity(of: child.processIdentifier) == identity, "the same process reads the same")
        #expect(table.isRunning(identity))
        #expect(table.children(of: getpid()).contains(child.processIdentifier))
    }

    @Test func testNoIdentityForMissingPIDs() {
        #expect(table.identity(of: 0) == nil)
        #expect(table.identity(of: -1) == nil)
        #expect(table.children(of: 0) == [])
    }

    /// The review case: the recorded PID's process has exited. It is not signalled,
    /// and stop() returns at once.
    @Test func testARecordedPIDWhoseProcessExitedIsNotSignalled() throws {
        let child = try sleeper()
        let recorded = try #require(table.identity(of: child.processIdentifier))
        child.terminate()
        child.waitUntilExit()
        #expect(table.identity(of: recorded.pid) == nil)
        #expect(!table.isRunning(recorded))
        #expect(table.signal(SIGTERM, ifStill: recorded) == false)
        let began = Date()
        table.stop(recorded, first: SIGINT, grace: 2)
        #expect(Date().timeIntervalSince(began) < 0.5)
    }

    @Test func testSameExecutableStartedLaterIsAnotherProcess() throws {
        let first = try sleeper()
        let recorded = try #require(table.identity(of: first.processIdentifier))
        first.terminate()
        first.waitUntilExit()
        let second = try sleeper()
        defer { second.terminate(); second.waitUntilExit() }
        // Same executable; even if the PID were the same, the start time is not.
        let pretend = ProcessIdentity(pid: second.processIdentifier, startSeconds: recorded.startSeconds,
                                      startMicroseconds: recorded.startMicroseconds, executable: recorded.executable)
        #expect(!table.isRunning(pretend))
        #expect(table.signal(SIGTERM, ifStill: pretend) == false)
        #expect(second.isRunning)
    }

    @Test func testStopEndsTheRecordedProcess() throws {
        let child = try sleeper()
        let recorded = try #require(table.identity(of: child.processIdentifier))
        table.stop(recorded, first: SIGTERM, grace: 2)
        child.waitUntilExit()
        #expect(child.terminationReason == .uncaughtSignal && child.terminationStatus == SIGTERM)
    }

    // MARK: Fake table: the rules, independent of timing

    @Test func testAReusedPIDIsNotSignalled() {
        let processes = FakeProcessTable()
        let recorded = processes.spawn("/usr/sbin/pppd")
        processes.exit(recorded.pid)
        processes.reuse(recorded.pid, executable: "/usr/sbin/pppd")
        #expect(processes.signal(SIGTERM, ifStill: recorded) == false)
        processes.stop(recorded, first: SIGTERM, grace: 0.05)
        #expect(processes.signals.isEmpty)
        #expect(processes.isAlive(recorded.pid), "the other process with that PID is untouched")
    }

    @Test func testADifferentExecutableIsNotSignalled() {
        let processes = FakeProcessTable()
        let recorded = processes.spawn("/usr/sbin/pppd")
        let other = ProcessIdentity(pid: recorded.pid, startSeconds: recorded.startSeconds,
                                    startMicroseconds: recorded.startMicroseconds, executable: "/usr/bin/other")
        #expect(processes.signal(SIGTERM, ifStill: other) == false)
        #expect(processes.signals.isEmpty)
    }

    @Test func testStopEscalatesOnlyWhileItIsStillTheSameProcess() {
        let processes = FakeProcessTable()
        let stubborn = processes.spawn("/usr/sbin/pppd", ignoring: [SIGTERM])
        processes.stop(stubborn, first: SIGTERM, grace: 0.05)
        #expect(processes.signals == [.init(pid: stubborn.pid, signal: SIGTERM), .init(pid: stubborn.pid, signal: SIGKILL)])
        #expect(!processes.isAlive(stubborn.pid))

        let polite = FakeProcessTable()
        let quick = polite.spawn("/usr/sbin/pppd")
        polite.stop(quick, first: SIGTERM, grace: 0.05)
        #expect(polite.signals == [.init(pid: quick.pid, signal: SIGTERM)], "no SIGKILL once it is gone")
    }
}
