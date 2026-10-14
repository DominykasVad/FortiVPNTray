import Foundation

/// What the app asks the helper to connect to (PLAN.md 2.2).
///
/// Every way of making one validates it: the memberwise initialiser and the
/// JSON decoding the helper uses on whatever a caller sends. A value that
/// exists is valid. The helper never trusts that the app checked anything.
public struct ConnectRequest: Equatable, Sendable {
    public enum Auth: Equatable, Sendable {
        /// SAML login; openfortivpn listens on 127.0.0.1 at `listenPort` for the browser's callback.
        case saml(listenPort: Int)
    }

    public static let defaultSAMLListenPort = 8020
    public static let samlListenPorts = 1024...65535
    public static let ports = 1...65535
    public static let maxTrustedCerts = 16
    /// Larger request bodies are refused before they are parsed.
    public static let maxEncodedSize = 16 * 1024

    /// Why a request was refused. Descriptions never repeat the offending value.
    public enum Rejection: Error, Equatable, CustomStringConvertible {
        case tooLarge
        case malformed
        case host
        case port
        case realm
        case samlListenPort
        case trustedCert
        case tooManyTrustedCerts

        public var description: String {
            switch self {
            case .tooLarge: return "The connect request is too large."
            case .malformed: return "The connect request is malformed."
            case .host: return "The host must be a hostname or an IPv4 address."
            case .port: return "The port must be between 1 and 65535."
            case .realm: return "The realm must be 1–63 letters, digits, '.', '_' or '-', not starting with '-'."
            case .samlListenPort: return "The SAML listen port must be between 1024 and 65535."
            case .trustedCert: return "Each trusted certificate must be 64 lowercase hex digits."
            case .tooManyTrustedCerts: return "At most \(ConnectRequest.maxTrustedCerts) trusted certificates are allowed."
            }
        }
    }

    public let host: String
    public let port: Int
    public let realm: String?
    public let auth: Auth
    public let trustedCerts: [String]
    /// If the tunnel provides no DNS servers, keep the system resolvers the helper
    /// read itself before connecting. The app never sends resolver addresses.
    public let useSystemDNSFallback: Bool

    public init(host: String, port: Int, realm: String? = nil, auth: Auth = .saml(listenPort: defaultSAMLListenPort),
                trustedCerts: [String] = [], useSystemDNSFallback: Bool = true) throws(Rejection) {
        guard Validation.host(host) else { throw .host }
        guard Self.ports.contains(port) else { throw .port }
        if let realm { guard Validation.realm(realm) else { throw .realm } }
        switch auth {
        case .saml(let listenPort): guard Self.samlListenPorts.contains(listenPort) else { throw .samlListenPort }
        }
        guard trustedCerts.count <= Self.maxTrustedCerts else { throw .tooManyTrustedCerts }
        guard trustedCerts.allSatisfy(Validation.digest) else { throw .trustedCert }
        self.host = host
        self.port = port
        self.realm = realm
        self.auth = auth
        self.trustedCerts = trustedCerts
        self.useSystemDNSFallback = useSystemDNSFallback
    }

    /// Parses and validates what a caller sent. Unknown or missing keys and wrong types are `.malformed`.
    public init(json: Data) throws(Rejection) {
        guard json.count <= Self.maxEncodedSize else { throw .tooLarge }
        do {
            self = try JSONDecoder().decode(Self.self, from: json)
        } catch let rejection as Rejection {
            throw rejection
        } catch {
            throw .malformed
        }
    }

    /// The JSON the app sends.
    public func json() -> Data {
        // Encoding a struct of strings, integers and arrays cannot fail.
        try! JSONEncoder().encode(self)
    }
}

extension ConnectRequest: Codable {
    private enum Keys: String, CodingKey, CaseIterable { case host, port, realm, auth, trustedCerts, useSystemDNSFallback }
    private enum AuthKeys: String, CodingKey, CaseIterable { case method, listenPort }

    public init(from decoder: Decoder) throws {
        try StrictKeys.require(Keys.self, in: decoder)
        let c = try decoder.container(keyedBy: Keys.self)
        let authDecoder = try c.superDecoder(forKey: .auth)
        try StrictKeys.require(AuthKeys.self, in: authDecoder)
        let a = try authDecoder.container(keyedBy: AuthKeys.self)
        guard try a.decode(String.self, forKey: .method) == "saml" else { throw Rejection.malformed }
        try self.init(host: try c.decode(String.self, forKey: .host),
                      port: try c.decode(Int.self, forKey: .port),
                      realm: try c.decodeIfPresent(String.self, forKey: .realm),
                      auth: .saml(listenPort: try a.decode(Int.self, forKey: .listenPort)),
                      trustedCerts: try c.decode([String].self, forKey: .trustedCerts),
                      useSystemDNSFallback: try c.decode(Bool.self, forKey: .useSystemDNSFallback))
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: Keys.self)
        try c.encode(host, forKey: .host)
        try c.encode(port, forKey: .port)
        try c.encodeIfPresent(realm, forKey: .realm)
        var a = c.nestedContainer(keyedBy: AuthKeys.self, forKey: .auth)
        switch auth {
        case .saml(let listenPort):
            try a.encode("saml", forKey: .method)
            try a.encode(listenPort, forKey: .listenPort)
        }
        try c.encode(trustedCerts, forKey: .trustedCerts)
        try c.encode(useSystemDNSFallback, forKey: .useSystemDNSFallback)
    }
}

/// Rejects a JSON object that has any key the type does not know.
private enum StrictKeys {
    private struct AnyKey: CodingKey {
        let stringValue: String
        var intValue: Int? { nil }
        init(stringValue: String) { self.stringValue = stringValue }
        init?(intValue: Int) { nil }
    }

    static func require<Known: CodingKey & CaseIterable>(_ known: Known.Type, in decoder: Decoder) throws {
        let names = Set(Known.allCases.map(\.stringValue))
        let keys = try decoder.container(keyedBy: AnyKey.self).allKeys
        guard keys.allSatisfy({ names.contains($0.stringValue) }) else { throw ConnectRequest.Rejection.malformed }
    }
}

/// What `status()` reports.
public struct HelperStatus: Codable, Equatable, Sendable {
    public enum State: String, Codable, Sendable {
        case idle, connecting, connected, disconnecting
    }

    public var state: State
    public var sessionID: String?
    public var interface: String?
    public var vpnIP: String?
    public var since: Date?
    public var lastError: String?

    public init(state: State = .idle, sessionID: String? = nil, interface: String? = nil, vpnIP: String? = nil,
                since: Date? = nil, lastError: String? = nil) {
        self.state = state
        self.sessionID = sessionID
        self.interface = interface
        self.vpnIP = vpnIP
        self.since = since
        self.lastError = lastError
    }
}

/// What `readLog(sessionID:offset:)` returns: redacted lines from `offset` on, and where to continue.
public struct LogChunk: Codable, Equatable, Sendable {
    public var lines: [String]
    public var nextOffset: Int

    public init(lines: [String], nextOffset: Int) {
        self.lines = lines
        self.nextOffset = nextOffset
    }
}

/// The JSON coding used for structured values on the XPC connection.
public enum HelperWire {
    public static func encode<Value: Encodable>(_ value: Value) -> Data {
        // Only used on the types above, whose encoding cannot fail.
        try! JSONEncoder().encode(value)
    }

    public static func decode<Value: Decodable>(_ type: Value.Type, from data: Data) throws -> Value {
        try JSONDecoder().decode(type, from: data)
    }
}
