import Testing
import FortiVPNShared

struct ValidationTests {
    @Test func testHostnamesAccepted() {
        let label63 = String(repeating: "a", count: 63)
        let longest = [label63, label63, label63, String(repeating: "b", count: 61)].joined(separator: ".")
        #expect(longest.utf8.count == 253)
        for name in ["vpn.example.com", "VPN-1.Example.COM", "localhost", "a", "x1", "1.example.com", "a-b.c", label63, longest, "example.c0m"] {
            #expect(Validation.hostname(name), "\(name)")
        }
    }

    @Test func testHostnamesRejected() {
        let label63 = String(repeating: "a", count: 63)
        let tooLong = [label63, label63, label63, String(repeating: "b", count: 62)].joined(separator: ".")
        let bad = [
            "", ".", "-vpn.example.com", ".vpn.example.com", "vpn.example.com.", "vpn..example.com",
            "vpn-.example.com", "vpn.-example.com", "vpn.example-", label63 + "a.example.com", tooLong,
            "vpn_1.example.com", "vpn example.com", "vpn.example.com:8443", "https://vpn.example.com",
            "-c/tmp/x", "vpn\n.example.com", "vpn.example.com\0", "host=evil", "vpn.exämple.com", "vpn。example.com",
            // An all-digit last label is an address, not a name: these must pass `ipv4` or nothing.
            "192.0.2.1", "010.0.0.1", "192.0.2.256", "1", "4294967295", "example.123",
        ]
        for name in bad {
            #expect(!Validation.hostname(name), "\(name.debugDescription)")
        }
    }

    @Test func testIPv4Accepted() {
        for address in ["192.0.2.1", "0.0.0.0", "255.255.255.255", "198.51.100.10", "10.0.0.1", "100.64.0.1"] {
            #expect(Validation.ipv4(address), "\(address)")
        }
    }

    @Test func testIPv4Rejected() {
        let bad = [
            "", "192.0.2", "192.0.2.1.5", "192.0.2.", ".192.0.2.1", "192..2.1", "192.0.2.256", "256.0.0.0",
            "1000.0.0.1", "192.0.2.-1", "+192.0.2.1", " 192.0.2.1", "192.0.2.1 ", "192.0.2.1\n",
            // No leading zeros: `010` is octal to inet_aton.
            "010.0.0.1", "192.0.2.01", "192.00.2.1", "00.0.0.0", "192.0.2.001",
            "0x7f.0.0.1", "192.0.2.1a", "１９２.0.2.1", "4294967295", "::1",
        ]
        for address in bad {
            #expect(!Validation.ipv4(address), "\(address.debugDescription)")
        }
    }

    @Test func testHostIsAddressOrName() {
        #expect(Validation.host("vpn.example.com"))
        #expect(Validation.host("192.0.2.1"))
        #expect(!Validation.host("010.0.0.1"))
        #expect(!Validation.host("192.0.2.300"))
        #expect(!Validation.host("-c/tmp/x"))
    }

    @Test func testDigestIsLowercaseHexOnly() {
        let digest = String(repeating: "0123456789abcdef", count: 4)
        #expect(Validation.digest(digest))
        #expect(!Validation.digest(digest.uppercased()))
        #expect(!Validation.digest(String(digest.dropLast()) + "A"))
        #expect(!Validation.digest(String(digest.dropLast())))
        #expect(!Validation.digest(digest + "0"))
        #expect(!Validation.digest(String(digest.dropLast()) + "g"))
        #expect(!Validation.digest(String(digest.dropLast()) + "\n"))
        #expect(!Validation.digest(String(digest.dropLast()) + "="))
        #expect(!Validation.digest(String(repeating: "ab:", count: 21) + "a"))
        #expect(!Validation.digest(""))
    }

    @Test func testRealm() {
        for realm in ["staff", "a", "Staff_2.example-x", String(repeating: "r", count: 63)] {
            #expect(Validation.realm(realm), "\(realm)")
        }
        for realm in ["", String(repeating: "r", count: 64), "staff users", "staff\n", "a=b", "staff\0", "a/b", "a\\b", "ståff", "#staff"] {
            #expect(!Validation.realm(realm), "\(realm.debugDescription)")
        }
    }
}
