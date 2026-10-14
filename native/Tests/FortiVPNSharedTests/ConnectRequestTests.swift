import Testing
import Foundation
import FortiVPNShared

struct ConnectRequestTests {
    private typealias Rejection = ConnectRequest.Rejection
    private let cert = String(repeating: "0123456789abcdef", count: 4)

    private func expectRejected(_ expected: Rejection, sourceLocation: SourceLocation = #_sourceLocation,
                                _ make: () throws(Rejection) -> ConnectRequest) {
        do {
            let request = try make()
            Issue.record("accepted \(request)", sourceLocation: sourceLocation)
        } catch {
            #expect(error == expected, sourceLocation: sourceLocation)
        }
    }

    /// A valid request as a JSON object, to be modified by each test.
    private func object() -> [String: Any] {
        ["host": "vpn.example.com", "port": 8443, "realm": "staff",
         "auth": ["method": "saml", "listenPort": 8020],
         "trustedCerts": [cert], "useSystemDNSFallback": true]
    }

    private func decode(_ object: Any) throws(Rejection) -> ConnectRequest {
        try ConnectRequest(json: try! JSONSerialization.data(withJSONObject: object))
    }

    @Test func testValidRequest() throws {
        let request = try ConnectRequest(host: "vpn.example.com", port: 8443, realm: "staff", trustedCerts: [cert])
        #expect(request.auth == .saml(listenPort: 8020))
        #expect(try ConnectRequest(json: request.json()) == request)
        #expect(try decode(object()) == request)
        // Optional parts may be absent; the realm may be null or missing.
        let minimal = try ConnectRequest(host: "192.0.2.1", port: 443)
        #expect(minimal.realm == nil && minimal.trustedCerts.isEmpty && minimal.useSystemDNSFallback)
        #expect(try ConnectRequest(json: minimal.json()) == minimal)
        var object = object()
        object["realm"] = NSNull()
        #expect(try decode(object).realm == nil)
        object["realm"] = nil
        #expect(try decode(object).realm == nil)
    }

    @Test func testWireFormat() throws {
        let request = try ConnectRequest(host: "vpn.example.com", port: 8443, realm: "staff", trustedCerts: [cert])
        let parsed = try #require(try JSONSerialization.jsonObject(with: request.json()) as? NSDictionary)
        #expect(parsed == object() as NSDictionary)
    }

    @Test func testHostRejected() {
        for host in ["", "-c/tmp/x", ".vpn.example.com", "vpn.example.com.", "vpn..example.com", "vpn-.example.com",
                     "010.0.0.1", "192.0.2.256", "vpn.example.com\n", "vpn.example.com\r", "vpn\0.example.com",
                     "host=evil", "vpn.example.com:8443", " vpn.example.com", "vpn.exämple.com"] {
            expectRejected(.host) { () throws(Rejection) in try ConnectRequest(host: host, port: 443) }
        }
    }

    @Test func testPortRejected() {
        for port in [0, -1, 65536, Int.max, Int.min] {
            expectRejected(.port) { () throws(Rejection) in try ConnectRequest(host: "vpn.example.com", port: port) }
        }
        for port in [1, 443, 65535] {
            #expect(throws: Never.self) { try ConnectRequest(host: "vpn.example.com", port: port) }
        }
    }

    @Test func testRealmRejected() {
        for realm in ["", String(repeating: "r", count: 64), "staff\n", "staff\r", "staff\0", "a=b", "staff users", "ståff"] {
            expectRejected(.realm) { () throws(Rejection) in try ConnectRequest(host: "vpn.example.com", port: 443, realm: realm) }
        }
    }

    @Test func testSAMLListenPortRejected() {
        for port in [0, 80, 1023, 65536, -8020] {
            expectRejected(.samlListenPort) { () throws(Rejection) in
                try ConnectRequest(host: "vpn.example.com", port: 443, auth: .saml(listenPort: port))
            }
        }
        for port in [1024, 8020, 65535] {
            #expect(throws: Never.self) { try ConnectRequest(host: "vpn.example.com", port: 443, auth: .saml(listenPort: port)) }
        }
    }

    @Test func testTrustedCertsRejected() {
        for bad in [cert.uppercased(), String(cert.dropLast()), cert + "0", String(cert.dropLast()) + "\n", "", "sha256:" + cert] {
            expectRejected(.trustedCert) { () throws(Rejection) in
                try ConnectRequest(host: "vpn.example.com", port: 443, trustedCerts: [cert, bad])
            }
        }
        let sixteen = Array(repeating: cert, count: 16)
        #expect(throws: Never.self) { try ConnectRequest(host: "vpn.example.com", port: 443, trustedCerts: sixteen) }
        expectRejected(.tooManyTrustedCerts) { () throws(Rejection) in
            try ConnectRequest(host: "vpn.example.com", port: 443, trustedCerts: sixteen + [cert])
        }
    }

    @Test func testDNSFallbackIsOnlyAFlag() throws {
        #expect(try ConnectRequest(host: "vpn.example.com", port: 443).useSystemDNSFallback)
        let off = try ConnectRequest(host: "vpn.example.com", port: 443, useSystemDNSFallback: false)
        #expect(!off.useSystemDNSFallback)
        #expect(try ConnectRequest(json: off.json()) == off)
        // Resolver addresses from the caller are refused, alone or next to the flag.
        var object = object()
        object["dnsFallback"] = ["192.0.2.53"]
        expectRejected(.malformed) { () throws(Rejection) in try decode(object) }
        object["useSystemDNSFallback"] = nil
        expectRejected(.malformed) { () throws(Rejection) in try decode(object) }
    }

    @Test func testDecodedRequestsAreValidated() {
        // The same rules apply to JSON from a caller as to the initialiser.
        let cases: [(String, Any, Rejection)] = [
            ("host", "-c/tmp/x", .host), ("port", 0, .port), ("realm", "a\nb", .realm),
            ("auth", ["method": "saml", "listenPort": 80], .samlListenPort),
            ("trustedCerts", [cert.uppercased()], .trustedCert),
            ("trustedCerts", Array(repeating: cert, count: 17), .tooManyTrustedCerts),
        ]
        for (key, value, expected) in cases {
            var object = object()
            object[key] = value
            expectRejected(expected) { () throws(Rejection) in try decode(object) }
        }
    }

    @Test func testMalformedJSONRejected() {
        let mutations: [(inout [String: Any]) -> Void] = [
            { $0["extraArgs"] = ["--pppd-plugin=/tmp/x"] },
            { $0["password"] = "secret" },
            { $0["auth"] = ["method": "saml", "listenPort": 8020, "username": "alice"] },
            { $0["auth"] = ["method": "password", "listenPort": 8020] },
            { $0["auth"] = ["listenPort": 8020] },
            { $0["auth"] = "saml" },
            { $0["auth"] = nil },
            { $0["host"] = nil },
            { $0["port"] = nil },
            { $0["trustedCerts"] = nil },
            { $0["useSystemDNSFallback"] = nil },
            { $0["port"] = "8443" },
            { $0["port"] = 8443.5 },
            { $0["port"] = true },
            { $0["host"] = ["vpn.example.com"] },
            { $0["realm"] = 7 },
            { $0["trustedCerts"] = cert },
            { $0["useSystemDNSFallback"] = 1 },
            { $0["useSystemDNSFallback"] = "true" },
        ]
        for mutate in mutations {
            var object = object()
            mutate(&object)
            expectRejected(.malformed) { () throws(Rejection) in try decode(object) }
        }
        for text in ["", "null", "[]", "\"vpn.example.com\"", "{", "{}", "not json"] {
            expectRejected(.malformed) { () throws(Rejection) in try ConnectRequest(json: Data(text.utf8)) }
        }
    }

    @Test func testOversizedRequestRejectedBeforeParsing() throws {
        let padding = Data(repeating: 0x20, count: ConnectRequest.maxEncodedSize)
        let request = try ConnectRequest(host: "vpn.example.com", port: 443)
        expectRejected(.tooLarge) { () throws(Rejection) in try ConnectRequest(json: request.json() + padding) }
        expectRejected(.tooLarge) { () throws(Rejection) in try ConnectRequest(json: Data(repeating: 0, count: ConnectRequest.maxEncodedSize + 1)) }
    }

    @Test func testRejectionDescriptionsAreFixedAndDistinct() {
        // Cases carry no values, so a description can never echo what the caller sent.
        let all: [Rejection] = [.tooLarge, .malformed, .host, .port, .realm, .samlListenPort, .trustedCert,
                                .tooManyTrustedCerts]
        #expect(Set(all.map(\.description)).count == all.count)
    }

    @Test func testStatusAndLogChunkRoundTrip() throws {
        let status = HelperStatus(state: .connected, sessionID: "id", interface: "ppp0", vpnIP: "198.51.100.7",
                                  since: Date(timeIntervalSince1970: 1_700_000_000), lastError: nil)
        #expect(try HelperWire.decode(HelperStatus.self, from: HelperWire.encode(status)) == status)
        #expect(try HelperWire.decode(HelperStatus.self, from: HelperWire.encode(HelperStatus())) == HelperStatus())
        let chunk = LogChunk(lines: ["a", "b"], nextOffset: 2)
        #expect(try HelperWire.decode(LogChunk.self, from: HelperWire.encode(chunk)) == chunk)
    }
}
