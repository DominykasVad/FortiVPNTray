import Foundation

// Helper probe (PLAN.md 4.2 prep): a stand-in for a hostile or foreign client of the
// installed helper. Built twice from this file, signed differently (build.sh). It talks
// to the helper's Mach service over the real XPC protocol, compiled in from
// FortiVPNShared, and sends whatever bytes it is given: no app-side validation.
//
//   probe version              ACCEPTED (and the helper's answer) or REJECTED
//   probe connect <file.json>  the same, then sends the file's bytes as the connect request
//
// Exit status: 0 accepted (and, for connect, the request refused), 1 rejected,
// 2 no answer, 3 connect accepted (unexpected; the probe disconnected at once), 64 usage.

/// Filled in by XPC callbacks, read after `done` is signalled.
final class Reply: @unchecked Sendable {
    // @unchecked Sendable: each field is written once, before `done.signal()`, and read after `done.wait`.
    let done = DispatchSemaphore(value: 0)
    var error: String?
    var version: (String, Int, String)?
    var connect: (String?, String?)?
    var disconnectError: String??
}

/// How long to wait for any one answer.
let wait: TimeInterval = 10

// XPC runs its handlers on its own queue. Top-level code in main.swift is main-actor
// isolated in Swift 6, so the handlers are made in nonisolated functions and are @Sendable.
nonisolated func call(_ connection: NSXPCConnection, _ body: (HelperXPCProtocol, Reply) -> Void) -> Reply {
    let reply = Reply()
    let proxy = connection.remoteObjectProxyWithErrorHandler { @Sendable error in
        reply.error = error.localizedDescription + " (\((error as NSError).domain) \((error as NSError).code))"
        reply.done.signal()
    } as? HelperXPCProtocol
    guard let proxy else {
        reply.error = "could not create the proxy"
        return reply
    }
    body(proxy, reply)
    if reply.done.wait(timeout: .now() + wait) == .timedOut, reply.error == nil {
        reply.error = "no answer within \(Int(wait)) seconds"
    }
    return reply
}

nonisolated func version(_ connection: NSXPCConnection) -> Reply {
    call(connection) { proxy, reply in
        proxy.version { version, protocolVersion, mode in
            reply.version = (version, protocolVersion, mode)
            reply.done.signal()
        }
    }
}

nonisolated func connect(_ connection: NSXPCConnection, _ request: Data) -> Reply {
    call(connection) { proxy, reply in
        proxy.connect(request) { sessionID, error in
            reply.connect = (sessionID, error)
            reply.done.signal()
        }
    }
}

nonisolated func disconnect(_ connection: NSXPCConnection) -> Reply {
    call(connection) { proxy, reply in
        proxy.disconnect { error in
            reply.disconnectError = .some(error)
            reply.done.signal()
        }
    }
}

let arguments = Array(CommandLine.arguments.dropFirst())
let usage = "usage: probe version | probe connect <request.json>"
var request: Data?
switch arguments.first {
case "version" where arguments.count == 1:
    break
case "connect" where arguments.count == 2:
    guard let data = FileManager.default.contents(atPath: arguments[1]) else {
        FileHandle.standardError.write(Data("cannot read \(arguments[1])\n".utf8))
        exit(64)
    }
    request = data
default:
    FileHandle.standardError.write(Data((usage + "\n").utf8))
    exit(64)
}

let service = HelperTransport.machServiceName
let connection = NSXPCConnection(machServiceName: service, options: .privileged)
connection.remoteObjectInterface = NSXPCInterface(with: HelperXPCProtocol.self)
connection.resume()
print("probe: uid \(getuid()), service \(service)")

let answer = version(connection)
guard let (helperVersion, protocolVersion, mode) = answer.version else {
    let noAnswer = answer.error?.hasPrefix("no answer") == true
    print(noAnswer ? "NO ANSWER: \(answer.error!)" : "REJECTED: \(answer.error ?? "no reply")")
    connection.invalidate()
    exit(noAnswer ? 2 : 1)
}
print("ACCEPTED: helper \(helperVersion), protocol \(protocolVersion), caller check \(mode)")

guard let request else {
    connection.invalidate()
    exit(0)
}
print("probe: sending \(request.count) bytes from \(arguments[1]) as the connect request")
let result = connect(connection, request)
switch result.connect {
case (_, let error?)?:
    print("CONNECT REFUSED: \(error)")
    connection.invalidate()
    exit(0)
case (let sessionID?, nil)?:
    // Nothing the probe sends should get this far. End the session at once.
    print("CONNECT ACCEPTED (unexpected): session \(sessionID); disconnecting")
    let ended = disconnect(connection)
    print(ended.disconnectError.map { "disconnect: \($0 ?? "done")" } ?? "disconnect: \(ended.error ?? "no reply")")
    connection.invalidate()
    exit(3)
default:
    print("CONNECT: no reply: \(result.error ?? "nothing")")
    connection.invalidate()
    exit(2)
}
