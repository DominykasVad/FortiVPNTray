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

    // MARK: Whole sessions in openfortivpn 1.24.1's own words

    static let cookie = "4f1d0c9a8b7e6d5c4b3a29181716151413121110"
    static let samlID = "0123456789abcdef0123456789abcdef"
    static let startURL = "https://vpn.example.com:10443/remote/saml/start?redirect=1"

    /// A SAML session with `-v` on a pipe, as the helper reads it, line for line from
    /// openfortivpn 1.24.1's source (`main.c`, `http_server.c`, `tunnel.c`, `http.c`,
    /// `io.c`; `log.c` prefixes, no colour). Gateway, addresses and secrets are made up.
    static let sessionUp = [
        "DEBUG:  openfortivpn 1.24.1",
        "DEBUG:  Loaded configuration file \"\(AppIdentity.helperRunDirectory)/6F9619FF-8B86-D011-B42D-00C04FC964FF.conf\".",
        "DEBUG:  Configuration host = \"vpn.example.com\"",
        "DEBUG:  Configuration realm = \"\"",
        "DEBUG:  Configuration port = \"10443\"",
        "INFO:   Listening for SAML login on port 8020",
        "INFO:   Authenticate at '\(startURL)'",
        "DEBUG:  Incoming HTTP connection",
        "INFO:   Processing HTTP SAML request",
        "DEBUG:  Resolving gateway host ip",
        "DEBUG:  Establishing TLS connection",
        "INFO:   Connected to gateway.",
        "DEBUG:  Using SAML authentication URL /remote/saml/auth_id?id=\(samlID)",
        "DEBUG:  Cookie: SVPNCOOKIE=\(cookie)",
        "INFO:   Authenticated.",
        "DEBUG:  Cookie: SVPNCOOKIE=\(cookie)",
        "INFO:   Remote gateway has allocated a VPN.",
        "DEBUG:  Retrieving configuration",
        "DEBUG:  Found dns suffix corp.example.com;example.lt in xml config",
        "DEBUG:  Found dns server 192.0.2.53 in xml config",
        "DEBUG:  Found dns server 192.0.2.54 in xml config",
        "DEBUG:  Establishing the tunnel",
        "DEBUG:  ppp_path: /usr/sbin/pppd",
        "DEBUG:  Switch to tunneling mode",
        "DEBUG:  Starting IO through the tunnel",
        "DEBUG:  gateway ---> pppd (24 bytes)",
        "INFO:   Got addresses: [198.51.100.7], ns [192.0.2.53, 192.0.2.54], ns_suffix [corp.example.com;example.lt]",
        "INFO:   Negotiation complete.",
        "INFO:   Interface ppp0 is UP.",
        "INFO:   Setting new routes...",
        "INFO:   Tunnel is up and running.",
    ]

    /// After SIGINT (`io.c` `io_loop`, `tunnel.c` `run_tunnel`, `pppd_terminate`).
    static let sessionDown = [
        "INFO:   Cancelling threads...",
        "INFO:   Cleanup, joining threads...",
        "DEBUG:  Disconnecting",
        "INFO:   Setting ppp0 interface down.",
        "INFO:   Restoring routes...",
        "DEBUG:  Waiting for pppd to exit...",
        "DEBUG:  waitpid: pppd exit status code 16",
        "INFO:   pppd: The link was terminated by the modem hanging up.",
        "INFO:   Terminated pppd.",
        "INFO:   Closed connection to gateway.",
        "INFO:   Logged out.",
    ]

    private func expectSessionState(_ parser: LogParser, sourceLocation: SourceLocation = #_sourceLocation) {
        #expect(parser.localIP == "198.51.100.7", sourceLocation: sourceLocation)
        #expect(parser.dnsServers == ["192.0.2.53", "192.0.2.54"], sourceLocation: sourceLocation)
        #expect(parser.dnsSuffixes == ["corp.example.com", "example.lt"], sourceLocation: sourceLocation)
        #expect(parser.effectiveDNS(fallback: ["198.51.100.53"]) == ["192.0.2.53", "192.0.2.54"], sourceLocation: sourceLocation)
        #expect(parser.lastError == nil, sourceLocation: sourceLocation)
    }

    /// The helper parses the raw lines. openfortivpn 1.24.1 never prints "Tunnel is down":
    /// the end of a session comes from the child's exit, not from the log (decision log, 3.1).
    @Test func testAWholeSessionAsTheHelperReadsIt() {
        var parser = LogParser()
        #expect(Self.sessionUp.flatMap { parser.consume($0) } == [.saml(URL(string: Self.startURL)!), .connected("198.51.100.7")])
        #expect(Self.sessionDown.flatMap { parser.consume($0) } == [])
        expectSessionState(parser)
    }

    /// The app reads the lines the helper serves: redacted. Only the lines with the start
    /// URL, the SAML session id and the cookie change, and the session state is the same.
    @Test func testTheSameSessionAsTheAppReadsIt() {
        let raw = Self.sessionUp + Self.sessionDown
        let served = raw.map(LogParser.redacted)
        #expect(zip(raw, served).filter { $0 != $1 }.map(\.1) == [
            "INFO:   Authenticate at '[redacted]",
            "DEBUG:  Using SAML authentication URL [redacted]",
            "DEBUG:  Cookie: [redacted]",
            "DEBUG:  Cookie: [redacted]",
        ])
        let text = served.joined(separator: "\n")
        #expect(!text.contains(Self.cookie) && !text.contains(Self.samlID) && !text.contains("://"))
        var parser = LogParser()
        #expect(served.flatMap { parser.consume($0) } == [.connected("198.51.100.7")])
        expectSessionState(parser)
    }

    /// A gateway that pushes no DNS: the system resolvers the helper read stay in use.
    @Test func testASessionWithoutVPNDNS() {
        var parser = LogParser()
        let lines = Self.sessionUp.filter { !$0.contains("Found dns") }
            .map { $0.hasPrefix("INFO:   Got addresses:") ? "INFO:   Got addresses: [198.51.100.7], ns [0.0.0.0, 0.0.0.0]" : $0 }
        #expect(lines.flatMap { parser.consume($0) }.last == .connected("198.51.100.7"))
        #expect(parser.dnsServers.isEmpty && parser.dnsSuffixes.isEmpty)
        #expect(parser.effectiveDNS(fallback: ["198.51.100.53"]) == ["198.51.100.53"])
    }

    /// How sessions that never come up end (`http_server.c`, `main.c`, `tunnel.c`): the last
    /// `ERROR:` line is kept, no tunnel is reported.
    @Test func testFailedSessionsKeepTheirLastError() {
        let start = Array(Self.sessionUp.prefix(5))
        let failures: [(lines: [String], lastError: String)] = [
            (["ERROR:  Failed to bind socket to port 8020", "ERROR:  Failed to retrieve SAML cookie from HTTP"],
             "ERROR:  Failed to retrieve SAML cookie from HTTP"),
            (["INFO:   Listening for SAML login on port 8020", "INFO:   Authenticate at '\(Self.startURL)'",
              "DEBUG:  Timeout listening for incoming HTTP connection reached",
              "ERROR:  Finally failed to retrieve SAML authentication token", "ERROR:  Failed to retrieve SAML cookie from HTTP"],
             "ERROR:  Failed to retrieve SAML cookie from HTTP"),
            (Array(Self.sessionUp[5...11]) + ["DEBUG:  Using SAML authentication URL /remote/saml/auth_id?id=\(Self.samlID)",
              "ERROR:  Could not authenticate to gateway. Please check the password, client certificate, etc.",
              "INFO:   Closed connection to gateway.", "INFO:   Logged out."],
             "ERROR:  Could not authenticate to gateway. Please check the password, client certificate, etc."),
        ]
        for failure in failures {
            var parser = LogParser()
            let events = (start + failure.lines).flatMap { parser.consume($0) }
            #expect(!events.contains { if case .connected = $0 { true } else { false } }, "\(events)")
            #expect(parser.lastError == failure.lastError)
            #expect(parser.localIP == nil)
        }
    }
}
