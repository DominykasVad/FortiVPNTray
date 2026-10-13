import Foundation

// Spike S1 client. The three test clients are this same program, signed differently.
// Exit status: 0 accepted, 1 rejected, 2 no answer, 64 usage.

final class Outcome: @unchecked Sendable {
    // @unchecked Sendable: written once from an XPC callback, read only after `finished` is signalled.
    var status: Int32 = 2
    var text = "NO ANSWER within 5 seconds"
}

// XPC calls its handlers on its own queue. Top-level code in main.swift is main-actor
// isolated in Swift 6, and a closure written there traps when it runs anywhere else,
// so the handlers are created in a nonisolated function and marked @Sendable.
nonisolated func ask(service: String) -> Outcome {
    let connection = NSXPCConnection(machServiceName: service, options: .privileged)
    connection.remoteObjectInterface = NSXPCInterface(with: SpikeProtocol.self)
    connection.resume()
    defer { connection.invalidate() }

    let finished = DispatchSemaphore(value: 0)
    let outcome = Outcome()
    let proxy = connection.remoteObjectProxyWithErrorHandler { @Sendable error in
        outcome.status = 1
        outcome.text = "REJECTED: \(error.localizedDescription)"
        finished.signal()
    } as? SpikeProtocol
    guard let proxy else {
        outcome.text = "could not create the proxy"
        return outcome
    }
    proxy.whoAmI { answer in
        outcome.status = 0
        outcome.text = "ACCEPTED: daemon says \(answer)"
        finished.signal()
    }
    _ = finished.wait(timeout: .now() + 5)
    return outcome
}

guard CommandLine.arguments.count == 2 else {
    print("usage: client <mach service name>")
    exit(64)
}
let outcome = ask(service: CommandLine.arguments[1])
print("\(outcome.text) [\(buildNote)]")
exit(outcome.status)
