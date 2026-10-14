import Testing
import Foundation
import FortiVPNShared

/// `LogParser` on openfortivpn's output (PLAN.md 4.1). Moved from CoreTests: the parser
/// lives in FortiVPNShared.
struct LogParserTests {
    @Test func testParserFindsIPAfterTimestamp() {
        var parser = LogParser()
        _ = parser.consume("[2026-09-25T09:00:00Z] DEBUG: Got addresses: [10.2.3.4], peer [10.0.0.1]")
        #expect(parser.consume("INFO: Tunnel is up and running.") == [.connected("10.2.3.4")])
    }
    @Test func testParserSupportsPPPLocalIP() {
        var parser = LogParser()
        _ = parser.consume("local  IP address 10.4.5.6")
        #expect(parser.localIP == "10.4.5.6")
    }
    @Test func testVPNDNSExcludesFallback() {
        var parser = LogParser()
        _ = parser.consume("DEBUG: Found dns server 10.0.0.53 in xml config")
        _ = parser.consume("DEBUG: Found dns suffix a.example.com;b.example.com,a.example.com in xml config")
        #expect(parser.effectiveDNS(fallback: ["8.8.8.8"]) == ["10.0.0.53"])
        #expect(parser.dnsSuffixes == ["a.example.com", "b.example.com"])
    }
    @Test func testDNSFallbackUsedOnlyWhenVPNProvidesNone() {
        var parser = LogParser()
        #expect(parser.effectiveDNS(fallback: ["192.168.1.1"]) == ["192.168.1.1"])
        _ = parser.consume("Found dns server 999.1.1.1")
        #expect(parser.dnsServers == [])
    }
    @Test func testCertificateReportedOnceAfterFailure() {
        var parser = LogParser()
        let digest = String(repeating: "ab", count: 32)
        // openfortivpn's exact lines (tunnel.c); before the failure line nothing counts.
        let failure = "ERROR:  Gateway certificate validation failed, and the certificate digest is not in the local whitelist. If you trust it, rerun with:"
        #expect(parser.consume("ERROR:      --trusted-cert " + digest) == [])
        _ = parser.consume(failure)
        #expect(parser.consume("ERROR:      --trusted-cert " + digest) == [.certificate(digest)])
        _ = parser.consume(failure)
        #expect(parser.consume("ERROR:      --trusted-cert " + digest) == []) // reported once
    }
    @Test func testSAMLURLDetectedOnceAndRejectsNonLocalHTTP() {
        var parser = LogParser()
        let url = URL(string: "https://vpn.example.com/remote/saml/start?x=1")!
        #expect(parser.consume("SAML login: \(url)") == [.saml(url)])
        #expect(parser.consume("SAML login: \(url)") == [])
        #expect(parser.consume("saml http://insecure.example.com/") == [])
    }
    @Test func testLogsRedactSecretsAndURLs() {
        let safe = LogParser.redacted("password=secret cookie: token123 https://vpn.example.com/?token=123")
        #expect(!safe.contains("secret")); #expect(!safe.contains("token123")); #expect(!safe.contains("token=123"))
    }
    @Test func testTunnelDownAndLastError() {
        var parser = LogParser()
        _ = parser.consume("ERROR: Authentication failed")
        #expect(parser.lastError == "ERROR: Authentication failed")
        #expect(parser.consume("INFO: Tunnel is down") == [.disconnected])
    }
}
