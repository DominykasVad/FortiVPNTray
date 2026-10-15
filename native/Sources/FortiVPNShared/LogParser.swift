import Foundation

public enum LogEvent: Equatable, Sendable {
    case connected(String), saml(URL), certificate(String)
}

public struct LogParser {
    public private(set) var dnsServers: [String] = []
    public private(set) var dnsSuffixes: [String] = []
    public private(set) var localIP: String?
    public private(set) var lastError: String?
    /// Set by openfortivpn's failure line; only the line right after it may carry the digest.
    private var digestLineNext = false
    private var reportedCertificates: Set<String> = []
    private var reportedURLs: Set<URL> = []
    /// Gateway-pushed suffixes kept at most (decision log, 3.1 fix).
    public static let maxDNSSuffixes = 16
    public init() {}
    public mutating func consume(_ line: String) -> [LogEvent] {
        var events: [LogEvent] = []
        if line.contains("ERROR:") { lastError = Self.redacted(line) }
        if let ip = Self.capture(#"Found dns server ([0-9.]+)"#, line), Validation.ipv4(ip), !dnsServers.contains(ip) { dnsServers.append(ip) }
        // openfortivpn prints the gateway's whole `domain=` value (`http.c`), so a list of
        // suffixes arrives in one line, separated by ';' (and possibly spaces).
        if let suffixes = Self.capture(#"Found dns suffix (.*?)(?: in xml config)?$"#, line) {
            for suffix in suffixes.split(whereSeparator: { $0 == ";" || $0 == "," || $0.isWhitespace }).map(String.init)
            where dnsSuffixes.count < Self.maxDNSSuffixes && Validation.hostname(suffix) && !dnsSuffixes.contains(suffix) {
                dnsSuffixes.append(suffix)
            }
        }
        for pattern in [#"Got addresses: \[([0-9.]+)\]"#, #"local\s+IP address\s+([0-9.]+)"#, #"local IP is\s+([0-9.]+)"#] {
            if let ip = Self.capture(pattern, line), Validation.ipv4(ip) { localIP = ip }
        }
        // openfortivpn (`tunnel.c`, `ssl_verify_cert`) prints the failure line, then at once
        // "    --trusted-cert <digest>". The certificate's subject and issuer follow, one
        // component per line and split at '/', so the gateway controls those lines: only
        // the exact line straight after the failure line, at its exact indent, is taken.
        if digestLineNext {
            digestLineNext = false
            if let digest = Self.capture(#"^ERROR:      --trusted-cert ([0-9a-f]{64})$"#, line), Validation.digest(digest), reportedCertificates.insert(digest).inserted {
                events.append(.certificate(digest))
            }
        }
        if line.hasPrefix("ERROR:  Gateway certificate validation failed, and the certificate digest is not in the local whitelist.") {
            digestLineNext = true
        }
        if line.lowercased().contains("saml"), let raw = Self.capture(#"(https?://[^\s\"'<>]+)"#, line), let url = URL(string: raw), let host = url.host,
           (url.scheme == "https" || host == "127.0.0.1" || host == "localhost"), reportedURLs.insert(url).inserted {
            events.append(.saml(url))
        }
        if line.contains("Tunnel is up and running") { events.append(.connected(localIP ?? "unknown")) }
        return events
    }
    public func effectiveDNS(fallback: [String]) -> [String] {
        // Never mix public resolvers into a VPN-provided split-DNS configuration.
        dnsServers.isEmpty ? fallback : dnsServers
    }
    /// Secrets that run to the end of the line. openfortivpn `-v` prints
    /// `Cookie: SVPNCOOKIE=…` and `Using SAML authentication URL /remote/saml/auth_id?id=…`
    /// (spikes/openfortivpn-config/FINDINGS.md, section 3); a cookie can carry further
    /// `; name=value` parts, so everything after the prefix goes.
    private static let restOfLine: [(pattern: String, template: String)] = [
        (#"(?i)(cookie\s*:).*"#, "$1 [redacted]"),
        (#"(?i)(SVPNCOOKIE).*"#, "$1=[redacted]"),
        (#"(?i)(SAML authentication URL).*"#, "$1 [redacted]"),
        (#"(?i)(/remote/saml/auth_id).*"#, "$1 [redacted]"),
    ]

    public static func redacted(_ line: String) -> String {
        var text = line
        for rule in restOfLine {
            text = text.replacingOccurrences(of: rule.pattern, with: rule.template, options: .regularExpression)
        }
        for pattern in [#"(?i)(password|passwd|cookie|authorization|token|SAMLResponse)\s*[:=]\s*(?!\[redacted\])\S+"#, #"https?://[^\s]+"#] {
            text = text.replacingOccurrences(of: pattern, with: "[redacted]", options: .regularExpression)
        }
        return text
    }
    public static func capture(_ pattern: String, _ line: String) -> String? {
        guard let regex = try? NSRegularExpression(pattern: pattern), let match = regex.firstMatch(in: line, range: NSRange(line.startIndex..., in: line)), let range = Range(match.range(at: 1), in: line) else { return nil }
        return String(line[range])
    }
}
