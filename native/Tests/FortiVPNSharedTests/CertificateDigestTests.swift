import Testing
import FortiVPNShared

/// The gateway certificate digest for the pin prompt (PLAN.md 3.2), taken from
/// openfortivpn's output as the helper serves it: redacted, line by line. Formats
/// from `tunnel.c` (`ssl_verify_cert`); certificate names and digests are made up.
struct CertificateDigestTests {
    static let digest = String(repeating: "3c", count: 32)
    static let other = String(repeating: "7e", count: 32)

    /// Exactly what openfortivpn 1.24.1 prints for an untrusted gateway certificate.
    static func failure(digest: String = digest, subject: [String] = ["C=LT", "O=Example", "CN=vpn.example.com"]) -> [String] {
        ["ERROR:  Gateway certificate validation failed, and the certificate digest is not in the local whitelist. If you trust it, rerun with:",
         "ERROR:      --trusted-cert \(digest)",
         "ERROR:  or add this line to your configuration file:",
         "ERROR:      trusted-cert = \(digest)",
         "ERROR:  Gateway certificate:",
         "ERROR:      subject:"]
        + subject.map { "ERROR:          \($0)" }
        + ["ERROR:      issuer:", "ERROR:          CN=Example CA", "ERROR:      sha256 digest:", "ERROR:          \(digest)"]
    }

    private func events(_ lines: [String]) -> [LogEvent] {
        var parser = LogParser()
        return lines.flatMap { parser.consume($0) }
    }

    @Test func testTheDigestSurvivesRedactionAndIsFoundOnce() {
        let served = Self.failure().map(LogParser.redacted)
        #expect(served == Self.failure(), "redaction leaves these lines alone")
        #expect(events(served) == [.certificate(Self.digest)])
    }

    /// The subject and issuer are the gateway's text, printed one '/'-component per line:
    /// a component that looks like openfortivpn's hint must not produce a prompt.
    @Test func testTheGatewayCannotSuggestADigest() {
        let injected = Self.failure(subject: ["CN=x", "--trusted-cert \(Self.other)",
                                              "Gateway certificate validation failed, and the certificate digest is not in the local whitelist.",
                                              "--trusted-cert \(Self.other)"])
        #expect(events(injected) == [.certificate(Self.digest)])
    }

    @Test func testOnlyTheExactHintLineCounts() {
        let failure = Self.failure()[0]
        for hint in ["ERROR:      --trusted-cert \(Self.digest.uppercased())",
                     "ERROR:      --trusted-cert=\(Self.digest)",
                     "ERROR:          --trusted-cert \(Self.digest)",
                     "ERROR:      --trusted-cert \(Self.digest) x",
                     "ERROR:      --trusted-cert \(Self.digest.dropLast())",
                     "INFO:       --trusted-cert \(Self.digest)"] {
            #expect(events([failure, hint]).isEmpty, "\(hint)")
        }
        // The hint must follow the failure line directly.
        #expect(events([failure, "ERROR:  something else", "ERROR:      --trusted-cert \(Self.digest)"]).isEmpty)
    }
}
