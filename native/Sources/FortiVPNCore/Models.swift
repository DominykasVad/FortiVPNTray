import Foundation
import FortiVPNShared

public struct VPNError: LocalizedError, Equatable {
    public let message: String
    public init(_ message: String) { self.message = message }
    public var errorDescription: String? { message }
}

public struct VPNProfile: Codable, Identifiable, Equatable, Sendable {
    public var id = UUID().uuidString
    public var name = ""
    public var host = ""
    public var port = 8443
    public var realm: String? = nil
    public var trustedCerts: [String] = []
    /// Where the SAML login page opens (PLAN.md 3.5): false = the app's own login window,
    /// true = the default browser. App-side only; never sent to the helper.
    public var samlExternalBrowser = false
    public init() {}
    /// SAML is the only authentication method (decision log, 1.3). Profiles written
    /// before 3.0 may still carry `auth_type` and `username`, and before 3.2
    /// `ignore_cert_errors` (F10); none of them is read or written back.
    enum CodingKeys: String, CodingKey {
        case id, name, host, port, realm
        case trustedCerts = "trusted_certs"
        case samlExternalBrowser = "saml_external_browser"
    }
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(String.self, forKey: .id)
        name = try c.decode(String.self, forKey: .name)
        host = try c.decode(String.self, forKey: .host)
        port = try c.decode(Int.self, forKey: .port)
        realm = try c.decodeIfPresent(String.self, forKey: .realm)
        trustedCerts = try c.decodeIfPresent([String].self, forKey: .trustedCerts) ?? []
        samlExternalBrowser = try c.decodeIfPresent(Bool.self, forKey: .samlExternalBrowser) ?? false
    }
    public func validated() throws -> VPNProfile {
        var result = self
        result.name = name.trimmingCharacters(in: .whitespacesAndNewlines)
        result.host = host.trimmingCharacters(in: .whitespacesAndNewlines)
        let realm = realm?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        result.realm = realm.isEmpty ? nil : realm
        // The helper accepts lowercase fingerprints only; stored or pasted uppercase ones are normalised here.
        result.trustedCerts = trustedCerts.map { $0.lowercased() }
        guard !result.name.isEmpty, Validation.host(result.host), (1...65535).contains(port) else {
            throw VPNError("Enter a name, a hostname or IPv4 address, and a port between 1 and 65535.")
        }
        guard result.realm.map(Validation.realm) != false else {
            throw VPNError("A realm may only contain letters, digits, '.', '_' and '-', at most 63 of them.")
        }
        guard !id.isEmpty, result.trustedCerts.allSatisfy(Validation.digest) else {
            throw VPNError("Each trusted certificate must be a 64-character SHA256 fingerprint.")
        }
        return result
    }
    public func arguments() throws -> [String] {
        let p = try validated()
        var args = ["\(p.host):\(p.port)", "--saml-login"]
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
