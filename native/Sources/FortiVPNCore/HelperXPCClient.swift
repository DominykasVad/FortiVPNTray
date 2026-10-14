import Foundation
import FortiVPNShared

/// What the running helper says about itself.
public struct HelperVersion: Equatable, Sendable {
    public let version: String
    public let protocolVersion: Int
    public let mode: CallerCheckMode

    public init(version: String, protocolVersion: Int, mode: CallerCheckMode) {
        self.version = version
        self.protocolVersion = protocolVersion
        self.mode = mode
    }
}

/// Calls the Swift helper over XPC. Only what the installer needs so far: the
/// version check (PLAN.md 2.6) and the session state before uninstalling.
/// Phase 3 turns this into the app's whole client.
public struct HelperXPCClient: Sendable {
    private let makeConnection: @Sendable () -> NSXPCConnection
    private let timeout: TimeInterval

    public init(timeout: TimeInterval = 2) {
        self.init(timeout: timeout) {
            NSXPCConnection(machServiceName: HelperTransport.machServiceName, options: .privileged)
        }
    }

    /// For tests: any connection, for example to an anonymous listener's endpoint.
    init(timeout: TimeInterval, makeConnection: @escaping @Sendable () -> NSXPCConnection) {
        self.makeConnection = makeConnection
        self.timeout = timeout
    }

    public func version() throws -> HelperVersion {
        try call { proxy, done in
            proxy.version { version, protocolVersion, mode in
                guard let mode = CallerCheckMode(rawValue: mode) else {
                    return done(.failure(VPNError("The helper reported an unknown caller check.")))
                }
                done(.success(HelperVersion(version: version, protocolVersion: protocolVersion, mode: mode)))
            }
        }
    }

    public func status() throws -> HelperStatus {
        try call { proxy, done in
            proxy.status { data in
                done(Result { try HelperWire.decode(HelperStatus.self, from: data) }.mapError { _ in VPNError("The helper sent an unreadable status.") })
            }
        }
    }

    /// One request on its own connection, waited for at most `timeout`.
    private func call<Value: Sendable>(_ body: (HelperXPCProtocol, @escaping @Sendable (Result<Value, VPNError>) -> Void) -> Void) throws -> Value {
        let connection = makeConnection()
        connection.remoteObjectInterface = NSXPCInterface(with: HelperXPCProtocol.self)
        connection.resume()
        defer { connection.invalidate() }
        let outcome = Outcome<Value>()
        let proxy = connection.remoteObjectProxyWithErrorHandler { _ in
            outcome.finish(.failure(VPNError("Helper unavailable. Install or repair it in Settings.")))
        }
        guard let helper = proxy as? HelperXPCProtocol else { throw VPNError("Helper unavailable. Install or repair it in Settings.") }
        body(helper) { outcome.finish($0) }
        guard let result = outcome.wait(timeout) else { throw VPNError("The helper did not answer in time.") }
        return try result.get()
    }
}

/// The first result of an XPC call, from whichever queue delivers it.
private final class Outcome<Value: Sendable>: @unchecked Sendable {
    // @unchecked Sendable: `result` is only touched while holding `lock`.
    private let lock = NSLock()
    private let done = DispatchSemaphore(value: 0)
    private var result: Result<Value, VPNError>?

    func finish(_ value: Result<Value, VPNError>) {
        let first = lock.withLock { () -> Bool in
            guard result == nil else { return false }
            result = value
            return true
        }
        if first { done.signal() }
    }

    func wait(_ timeout: TimeInterval) -> Result<Value, VPNError>? {
        guard done.wait(timeout: .now() + timeout) == .success else { return nil }
        return lock.withLock { result }
    }
}
