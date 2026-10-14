import Testing
import FortiVPNShared

/// `LogParser.redacted` on the secrets openfortivpn `-v` prints, in the exact formats
/// of spikes/openfortivpn-config/FINDINGS.md, section 3 (`http.c:446`, `tunnel.c:1392`,
/// `http.c:693`; `log.c` prefixes, no colour on a pipe). All values are made up.
struct RedactionTests {
    static let cookie = "4f1d0c9a8b7e6d5c4b3a29181716151413121110"
    static let samlID = "0123456789abcdef0123456789abcdef"

    @Test func testSessionCookieLineLosesTheWholeValue() {
        #expect(LogParser.redacted("DEBUG:  Cookie: SVPNCOOKIE=\(Self.cookie)") == "DEBUG:  Cookie: [redacted]")
        // A second `; name=value` part and anything after it go too.
        let twoParts = LogParser.redacted("DEBUG:  Cookie: SVPNCOOKIE=\(Self.cookie); SVPNNETWORKCOOKIE=abc")
        #expect(twoParts == "DEBUG:  Cookie: [redacted]")
        #expect(!twoParts.contains("abc"))
    }

    @Test func testSAMLSessionIDLineLosesTheID() {
        let line = "DEBUG:  Using SAML authentication URL /remote/saml/auth_id?id=\(Self.samlID)"
        #expect(LogParser.redacted(line) == "DEBUG:  Using SAML authentication URL [redacted]")
    }

    @Test func testCookieAndSessionIDAreRedactedAnywhereInALine() {
        for line in [
            "Set-Cookie: SVPNCOOKIE=\(Self.cookie); path=/; secure",
            "ERROR:  Bad cookie SVPNCOOKIE=\(Self.cookie)",
            "ERROR:  svpncookie=\(Self.cookie)",
            "GET /remote/saml/auth_id?id=\(Self.samlID) HTTP/1.1",
            "ERROR:  using saml authentication url /remote/saml/auth_id?id=\(Self.samlID)",
        ] {
            let safe = LogParser.redacted(line)
            #expect(!safe.contains(Self.cookie) && !safe.contains(Self.samlID), "\(safe)")
            #expect(safe.contains("[redacted]"))
        }
    }

    @Test func testSAMLStartURLIsRedacted() {
        let line = "INFO:   Authenticate at 'https://vpn.example.com:443/remote/saml/start?redirect=1&realm=staff'"
        #expect(LogParser.redacted(line) == "INFO:   Authenticate at '[redacted]")
    }

    @Test func testOrdinaryLinesAreUnchanged() {
        for line in [
            "INFO:   Connected to gateway.",
            "INFO:   Listening for SAML login on port 8020",
            "INFO:   Processing HTTP SAML request",
            "DEBUG:  Found dns server 192.0.2.53 in xml config",
            "DEBUG:  Found dns suffix example.com in xml config",
            "INFO:   Tunnel is up and running.",
            "ERROR:  Gateway certificate validation failed, and the certificate digest is not in the local whitelist.",
        ] {
            #expect(LogParser.redacted(line) == line)
        }
    }

    @Test func testRedactingTwiceChangesNothing() {
        for line in ["DEBUG:  Cookie: SVPNCOOKIE=\(Self.cookie)", "DEBUG:  Using SAML authentication URL /remote/saml/auth_id?id=\(Self.samlID)",
                     "password=secret token: abc"] {
            let once = LogParser.redacted(line)
            #expect(LogParser.redacted(once) == once)
        }
    }
}
