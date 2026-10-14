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

/// The helper's API as the app uses it (PLAN.md 2.2). Behind a protocol so
/// `VPNEngine` can be tested without a helper.
public protocol HelperAPI: Sendable {
    func version() throws -> HelperVersion
    func status() throws -> HelperStatus
    /// Starts a session; returns its id.
    func connect(_ request: ConnectRequest) throws -> String
    func disconnect() throws
    func readLog(sessionID: String, offset: Int) throws -> LogChunk
    func pendingSAMLURL() throws -> URL?
}

/// Calls the Swift helper over XPC. One connection is kept and reused, so polling
/// does not make the helper check the caller's code signature for every call;
/// it is made again after the helper went away.
public final class HelperXPCClient: HelperAPI, @unchecked Sendable {
    // @unchecked Sendable: `connection` is only touched while holding `lock`.
    private let makeConnection: @Sendable () -> NSXPCConnection
    private let timeout: TimeInterval
    private let longTimeout: TimeInterval
    private let lock = NSLock()
    private var connection: NSXPCConnection?

    /// `timeout` bounds quick calls; connect and disconnect, which start and clean up
    /// a whole session in the helper, may take up to `longTimeout`.
    public convenience init(timeout: TimeInterval = 5, longTimeout: TimeInterval = 120) {
        self.init(timeout: timeout, longTimeout: longTimeout) {
            NSXPCConnection(machServiceName: HelperTransport.machServiceName, options: .privileged)
        }
    }

    /// For tests: any connection, for example to an anonymous listener's endpoint.
    init(timeout: TimeInterval, longTimeout: TimeInterval? = nil, makeConnection: @escaping @Sendable () -> NSXPCConnection) {
        self.makeConnection = makeConnection
        self.timeout = timeout
        self.longTimeout = longTimeout ?? timeout
    }

    deinit {
        connection?.invalidate()
    }

    public func version() throws -> HelperVersion {
        try call(timeout) { proxy, done in
            proxy.version { version, protocolVersion, mode in
                guard let mode = CallerCheckMode(rawValue: mode) else {
                    return done(.failure(VPNError("The helper reported an unknown caller check.")))
                }
                done(.success(HelperVersion(version: version, protocolVersion: protocolVersion, mode: mode)))
            }
        }
    }

    public func status() throws -> HelperStatus {
        try call(timeout) { proxy, done in
            proxy.status { data in done(Self.decode(HelperStatus.self, data, what: "status")) }
        }
    }

    public func connect(_ request: ConnectRequest) throws -> String {
        try call(longTimeout) { proxy, done in
            proxy.connect(request.json()) { sessionID, error in
                if let sessionID, error == nil { done(.success(sessionID)) } else { done(.failure(VPNError(error ?? "The helper did not start a session."))) }
            }
        }
    }

    public func disconnect() throws {
        try call(longTimeout) { proxy, done in
            proxy.disconnect { error in done(error.map { .failure(VPNError($0)) } ?? .success(())) }
        }
    }

    public func readLog(sessionID: String, offset: Int) throws -> LogChunk {
        try call(timeout) { proxy, done in
            proxy.readLog(sessionID: sessionID, offset: offset) { data, error in
                if let data, error == nil { done(Self.decode(LogChunk.self, data, what: "log")) } else { done(.failure(VPNError(error ?? "The helper sent no log."))) }
            }
        }
    }

    public func pendingSAMLURL() throws -> URL? {
        try call(timeout) { proxy, done in
            proxy.pendingSAMLURL { text in done(.success(text.flatMap(URL.init(string:)))) }
        }
    }

    private static func decode<Value: Decodable>(_ type: Value.Type, _ data: Data, what: String) -> Result<Value, VPNError> {
        Result { try HelperWire.decode(type, from: data) }.mapError { _ in VPNError("The helper sent an unreadable \(what).") }
    }

    private func currentConnection() -> NSXPCConnection {
        lock.withLock {
            if let connection { return connection }
            let fresh = makeConnection()
            fresh.remoteObjectInterface = NSXPCInterface(with: HelperXPCProtocol.self)
            fresh.invalidationHandler = { [weak self, weak fresh] in self?.forget(fresh) }
            fresh.interruptionHandler = { [weak self, weak fresh] in self?.forget(fresh) }
            fresh.resume()
            connection = fresh
            return fresh
        }
    }

    private func forget(_ old: NSXPCConnection?) {
        let stale = lock.withLock { () -> NSXPCConnection? in
            guard let old, connection === old else { return nil }
            connection = nil
            return old
        }
        stale?.invalidate()
    }

    /// One request, waited for at most `limit`. A connection that failed or timed out
    /// is dropped, so the next call starts a fresh one.
    private func call<Value: Sendable>(_ limit: TimeInterval, _ body: (HelperXPCProtocol, @escaping @Sendable (Result<Value, VPNError>) -> Void) -> Void) throws -> Value {
        let connection = currentConnection()
        let outcome = Outcome<Value>()
        let proxy = connection.remoteObjectProxyWithErrorHandler { [weak self, weak connection] _ in
            self?.forget(connection)
            outcome.finish(.failure(VPNError("Helper unavailable. Install or repair it in Settings.")))
        }
        guard let helper = proxy as? HelperXPCProtocol else { throw VPNError("Helper unavailable. Install or repair it in Settings.") }
        body(helper) { outcome.finish($0) }
        guard let result = outcome.wait(limit) else {
            forget(connection)
            throw VPNError("The helper did not answer in time.")
        }
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
