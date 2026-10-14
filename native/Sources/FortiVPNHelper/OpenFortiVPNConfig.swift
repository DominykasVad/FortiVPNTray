import Foundation
import FortiVPNShared

/// Writes the openfortivpn config file for a session (PLAN.md 2.3, S3).
///
/// `-c` replaces openfortivpn's default config entirely, and an unknown key
/// makes it drop the rest of the file, so only keys known to the pinned
/// openfortivpn version are written, in a fixed order. Values are never
/// escaped: anything openfortivpn's parser would read differently is refused.
enum OpenFortiVPNConfig {
    struct Unsafe: Error, Equatable, CustomStringConvertible {
        let key: String
        var description: String { "Refusing to write config key \(key)." }
    }

    /// The only keys this writer emits. All exist in openfortivpn 1.24.1's `load_config`.
    static let keys = ["set-dns", "pppd-use-peerdns", "host", "port", "saml-login", "realm", "trusted-cert"]

    static func render(_ request: ConnectRequest) throws -> String {
        var lines = [("set-dns", "0"), ("pppd-use-peerdns", "0"), ("host", request.host), ("port", String(request.port))]
        switch request.auth {
        case .saml(let listenPort): lines.append(("saml-login", String(listenPort)))
        }
        if let realm = request.realm { lines.append(("realm", realm)) }
        lines += request.trustedCerts.map { ("trusted-cert", $0) }
        return try lines.map { try line($0, $1) }.joined()
    }

    /// `key = value\n`. openfortivpn splits at the first `=`, trims whitespace on
    /// both sides and ends a value at the newline, so a value must be non-empty
    /// printable ASCII without `=` or spaces. That also excludes `\n`, `\r` and `\0`.
    static func line(_ key: String, _ value: String) throws -> String {
        guard keys.contains(key), !value.isEmpty,
              value.utf8.allSatisfy({ (0x21...0x7e).contains($0) && $0 != UInt8(ascii: "=") }) else {
            throw Unsafe(key: key)
        }
        return "\(key) = \(value)\n"
    }
}
