import Foundation

public struct VPNError: LocalizedError, Equatable {
    public let message: String
    public init(_ message: String) { self.message = message }
    public var errorDescription: String? { message }
}

public enum AuthType: String, Codable, CaseIterable, Identifiable, Sendable {
    case password = "Password", saml = "Saml"
    public var id: String { rawValue }
    public var title: String { self == .password ? "Password" : "SAML / SSO" }
}

public struct VPNProfile: Codable, Identifiable, Equatable, Sendable {
    public var id = UUID().uuidString
    public var name = ""
    public var host = ""
    public var port = 8443
    public var authType: AuthType = .password
    public var username: String? = nil
    public var realm: String? = nil
    public var trustedCerts: [String] = []
    public var ignoreCertErrors = false
    public init() {}
    enum CodingKeys: String, CodingKey {
        case id, name, host, port, username, realm
        case authType = "auth_type", trustedCerts = "trusted_certs"
        case ignoreCertErrors = "ignore_cert_errors"
    }
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(String.self, forKey: .id)
        name = try c.decode(String.self, forKey: .name)
        host = try c.decode(String.self, forKey: .host)
        port = try c.decode(Int.self, forKey: .port)
        authType = try c.decode(AuthType.self, forKey: .authType)
        username = try c.decodeIfPresent(String.self, forKey: .username)
        realm = try c.decodeIfPresent(String.self, forKey: .realm)
        trustedCerts = try c.decodeIfPresent([String].self, forKey: .trustedCerts) ?? []
        ignoreCertErrors = try c.decodeIfPresent(Bool.self, forKey: .ignoreCertErrors) ?? false
    }
    public func validated() throws -> VPNProfile {
        var result = self
        result.name = name.trimmingCharacters(in: .whitespacesAndNewlines)
        result.host = host.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !result.name.isEmpty, Validation.hostname(result.host), (1...65535).contains(port) else {
            throw VPNError("Enter a name, a hostname or IPv4 address, and a port between 1 and 65535.")
        }
        guard !id.isEmpty, trustedCerts.allSatisfy(Validation.digest) else {
            throw VPNError("Each trusted certificate must be a 64-character SHA256 fingerprint.")
        }
        return result
    }
    public func arguments(password: String?) throws -> [String] {
        let p = try validated()
        var args = ["\(p.host):\(p.port)"]
        if authType == .password {
            guard let user = username?.trimmingCharacters(in: .whitespacesAndNewlines), !user.isEmpty else {
                throw VPNError("Enter a username in the profile.")
            }
            guard let password, !password.isEmpty else { throw VPNError("Save a password in the profile before connecting.") }
            args += ["-u", user, "-p", password]
        } else { args += ["--saml-login"] }
        args += trustedCerts.map { "--trusted-cert=\($0)" }
        if let realm, !realm.isEmpty { args += ["--realm=\(realm)"] }
        args += ["--set-dns=0", "--pppd-use-peerdns=0", "-v"]
        return args
    }
}

public enum Validation {
    public static func hostname(_ text: String) -> Bool {
        !text.isEmpty && text.count <= 253 && text.first != "-" && text.first != "." &&
        text.utf8.allSatisfy { (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || $0 == 45 || $0 == 46 }
    }
    public static func ipv4(_ text: String) -> Bool {
        let parts = text.split(separator: ".", omittingEmptySubsequences: false)
        return parts.count == 4 && parts.allSatisfy { !$0.isEmpty && $0.allSatisfy(\.isNumber) && UInt8($0) != nil }
    }
    public static func digest(_ text: String) -> Bool { text.count == 64 && text.utf8.allSatisfy { (48...57).contains($0) || (65...70).contains($0) || (97...102).contains($0) } }
}

public struct AppSettings: Codable, Equatable, Sendable {
    public var debugMode = false
    public var helperDeclined = false
    public var dnsFallback = true
    public init() {}
    enum CodingKeys: String, CodingKey {
        case debugMode = "debug_mode", helperDeclined = "helper_declined", dnsFallback = "dns_fallback"
    }
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        debugMode = try c.decodeIfPresent(Bool.self, forKey: .debugMode) ?? false
        helperDeclined = try c.decodeIfPresent(Bool.self, forKey: .helperDeclined) ?? false
        dnsFallback = try c.decodeIfPresent(Bool.self, forKey: .dnsFallback) ?? true
    }
}
