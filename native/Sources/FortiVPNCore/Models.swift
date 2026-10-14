import Foundation
import FortiVPNShared

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
        // The helper accepts lowercase fingerprints only; stored or pasted uppercase ones are normalised here.
        result.trustedCerts = trustedCerts.map { $0.lowercased() }
        guard !result.name.isEmpty, Validation.host(result.host), (1...65535).contains(port) else {
            throw VPNError("Enter a name, a hostname or IPv4 address, and a port between 1 and 65535.")
        }
        guard !id.isEmpty, result.trustedCerts.allSatisfy(Validation.digest) else {
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
        args += p.trustedCerts.map { "--trusted-cert=\($0)" }
        if let realm, !realm.isEmpty { args += ["--realm=\(realm)"] }
        args += ["--set-dns=0", "--pppd-use-peerdns=0", "-v"]
        return args
    }
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
