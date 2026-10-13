import Foundation
import os

// Spike S1: a root launchd daemon that accepts XPC connections only from a
// client with a given signing identifier and certificate. Never part of the app.

let log = Logger(subsystem: "eu.dvad.fortivpntray.spike.xpc", category: "daemon")

func note(_ message: String) {
    log.notice("\(message, privacy: .public)")
    FileHandle.standardError.write(Data("\(message)\n".utf8))
}

func argument(_ name: String) -> String? {
    let arguments = CommandLine.arguments
    guard let index = arguments.firstIndex(of: name), index + 1 < arguments.count else { return nil }
    return arguments[index + 1]
}

final class Service: NSObject, SpikeProtocol {
    func whoAmI(reply: @escaping @Sendable (String) -> Void) {
        guard let connection = NSXPCConnection.current() else { return reply("no current connection") }
        let answer = "accepted pid=\(connection.processIdentifier) uid=\(connection.effectiveUserIdentifier)"
        note("whoAmI: \(answer)")
        reply(answer)
    }
}

final class ListenerDelegate: NSObject, NSXPCListenerDelegate {
    let requirement: String?
    let allowedUID: uid_t
    init(requirement: String?, allowedUID: uid_t) {
        self.requirement = requirement
        self.allowedUID = allowedUID
    }
    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        let uid = connection.effectiveUserIdentifier
        note("connection from pid=\(connection.processIdentifier) uid=\(uid)")
        guard uid == allowedUID else {
            note("refused: uid \(uid) is not the allowed uid \(allowedUID)")
            return false
        }
        if let requirement {
            // The requirement is checked by the system against the caller's audit token.
            // A caller that does not satisfy it has every message dropped and the connection invalidated.
            connection.setCodeSigningRequirement(requirement)
        }
        connection.exportedInterface = NSXPCInterface(with: SpikeProtocol.self)
        connection.exportedObject = Service()
        connection.resume()
        return true
    }
}

/// Unprivileged check of the same delegate and service over an anonymous listener in
/// this process. The peer is this binary, so `identifier` must be its own signing identifier.
nonisolated func selfTest(identifier: String, hash: String) -> Int32 {
    final class Answer: @unchecked Sendable {
        // @unchecked Sendable: written once from an XPC callback, read only after the semaphore is signalled.
        var text: String?
    }
    func ask(requirement: String?) -> String? {
        let delegate = ListenerDelegate(requirement: requirement, allowedUID: getuid())
        let listener = NSXPCListener.anonymous()
        listener.delegate = delegate
        listener.resume()
        defer { listener.invalidate() }
        let connection = NSXPCConnection(listenerEndpoint: listener.endpoint)
        connection.remoteObjectInterface = NSXPCInterface(with: SpikeProtocol.self)
        connection.resume()
        defer { connection.invalidate() }
        let finished = DispatchSemaphore(value: 0)
        let answer = Answer()
        let proxy = connection.remoteObjectProxyWithErrorHandler { @Sendable error in
            note("self-test error: \(error.localizedDescription)")
            finished.signal()
        } as? SpikeProtocol
        proxy?.whoAmI { text in
            answer.text = text
            finished.signal()
        }
        _ = finished.wait(timeout: .now() + 5)
        return answer.text
    }
    let cases: [(String, String?, Bool)] = [
        ("uid-only", nil, true),
        ("leaf, own identifier", "identifier \"\(identifier)\" and certificate leaf = H\"\(hash)\"", true),
        ("root, own identifier", "identifier \"\(identifier)\" and certificate root = H\"\(hash)\"", true),
        ("leaf, other identifier", "identifier \"\(identifier).other\" and certificate leaf = H\"\(hash)\"", false),
        ("leaf, other certificate", "identifier \"\(identifier)\" and certificate leaf = H\"\(String(repeating: "0", count: 40))\"", false),
    ]
    var failures: Int32 = 0
    for (name, requirement, expected) in cases {
        let accepted = ask(requirement: requirement) != nil
        if accepted != expected { failures += 1 }
        print("self-test \(name): \(accepted ? "accepted" : "rejected") \(accepted == expected ? "(ok)" : "(UNEXPECTED)")")
    }
    return failures
}

if CommandLine.arguments.contains("--self-test") {
    guard let identifier = argument("--client-id"), let hash = argument("--cert-sha1") else { exit(64) }
    exit(selfTest(identifier: identifier, hash: hash) == 0 ? 0 : 1)
}

guard let service = argument("--mach-service"),
      let uidText = argument("--allowed-uid"), let allowedUID = uid_t(uidText),
      let mode = argument("--mode") else {
    note("usage: daemon --mach-service <name> --allowed-uid <uid> --mode <leaf|root|uid-only> [--client-id <id> --cert-sha1 <hex>]")
    exit(64)
}

let requirement: String?
switch mode {
case "uid-only":
    requirement = nil
case "leaf", "root":
    guard let identifier = argument("--client-id"), let hash = argument("--cert-sha1"),
          identifier.range(of: "^[A-Za-z0-9.-]+$", options: .regularExpression) != nil,
          hash.range(of: "^[0-9A-Fa-f]{40}$", options: .regularExpression) != nil else {
        note("refusing to start: --client-id and a 40-digit --cert-sha1 are required in mode \(mode)")
        exit(64)
    }
    requirement = "identifier \"\(identifier)\" and certificate \(mode) = H\"\(hash)\""
default:
    note("refusing to start: unknown mode \(mode)")
    exit(64)
}

note("starting as uid=\(getuid()) service=\(service) allowed-uid=\(allowedUID) requirement=\(requirement ?? "none (uid-only)")")
let delegate = ListenerDelegate(requirement: requirement, allowedUID: allowedUID)
let listener = NSXPCListener(machServiceName: service)
listener.delegate = delegate
listener.resume()
RunLoop.main.run()
