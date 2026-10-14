import Foundation
import FortiVPNShared
import os

// Root helper, started by launchd. Everything it needs to know about its
// callers comes from its launch arguments; without valid ones it does not start.
//
// Top-level code here is main-actor isolated. XPC calls its delegate and
// handlers on its own queues, so nothing that XPC calls is defined in this file
// (S1: a closure written here traps when XPC runs it).

let log = Logger(subsystem: AppIdentity.helperLabel, category: "main")

let launchArguments: HelperLaunchArguments
do {
    launchArguments = try HelperLaunchArguments(parsing: Array(CommandLine.arguments.dropFirst()))
} catch {
    log.fault("Refusing to start: \(String(describing: error), privacy: .public)")
    exit(EX_USAGE)
}
guard let callerCheck = CallerCheck(arguments: launchArguments, sessions: SessionController(launcher: OpenFortiVPNLauncher())) else {
    log.fault("Refusing to start: the caller requirement could not be built")
    exit(EX_USAGE)
}

let listener = NSXPCListener(machServiceName: HelperTransport.machServiceName)
listener.delegate = callerCheck
listener.resume()
log.notice("Helper \(HelperTransport.helperVersion, privacy: .public) listening, caller check: \(launchArguments.callerCheck.mode.rawValue, privacy: .public), allowed uid \(launchArguments.allowedUID, privacy: .public)")
RunLoop.main.run()
