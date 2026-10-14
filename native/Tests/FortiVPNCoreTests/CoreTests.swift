import Testing
import Foundation
import Darwin
@testable import FortiVPNCore
import FortiVPNShared

struct CoreTests {
    private func profile() -> VPNProfile {
        var p = VPNProfile(); p.name = "Office"; p.host = "vpn.example.com"
        return p
    }
    @Test func testHelperInstallationClassifiesFilesAndServiceIndependently() {
        typealias Status = HelperInstallationStatus
        let current = HelperVersion(version: HelperTransport.helperVersion, protocolVersion: HelperTransport.protocolVersion, mode: .signed)
        // The version string may change freely; only the protocol decides (PLAN.md 2.6).
        let otherBuild = HelperVersion(version: "old", protocolVersion: HelperTransport.protocolVersion, mode: .signed)
        let otherProtocol = HelperVersion(version: HelperTransport.helperVersion, protocolVersion: HelperTransport.protocolVersion + 1, mode: .signed)
        expectEqual(Status(executablePresent: false, launchDaemonPresent: false, helper: nil).state, .missing)
        expectEqual(Status(executablePresent: true, launchDaemonPresent: false, helper: nil).state, .incomplete)
        expectEqual(Status(executablePresent: false, launchDaemonPresent: true, helper: nil).state, .incomplete)
        expectEqual(Status(executablePresent: true, launchDaemonPresent: true, helper: nil).state, .unavailable)
        expectEqual(Status(executablePresent: true, launchDaemonPresent: true, helper: current).state, .ready)
        expectEqual(Status(executablePresent: true, launchDaemonPresent: true, helper: otherBuild).state, .ready)
        expectEqual(Status(executablePresent: true, launchDaemonPresent: true, helper: otherProtocol).state, .versionMismatch)
        // A still-running process with removed files is not a verified installation/removal.
        expectEqual(Status(executablePresent: false, launchDaemonPresent: false, helper: current).state, .incomplete)
    }
    @Test func testHelperStatusShowsTheCallerCheckAndWarnsAboutUIDOnly() {
        let signed = HelperInstallationStatus(executablePresent: true, launchDaemonPresent: true,
                                              helper: HelperVersion(version: "0.3.0", protocolVersion: HelperTransport.protocolVersion, mode: .signed))
        expectEqual(signed.detail, "Version 0.3.0 · Ready to connect.")
        expectEqual(signed.callerCheck, "Caller check: Signed caller check")
        expectFalse(signed.callerCheckIsWeak)
        let uidOnly = HelperInstallationStatus(executablePresent: true, launchDaemonPresent: true,
                                               helper: HelperVersion(version: "0.3.0", protocolVersion: HelperTransport.protocolVersion, mode: .uidOnly))
        expectEqual(uidOnly.callerCheck, "Caller check: UID-only")
        expectTrue(uidOnly.callerCheckIsWeak)
        // No answer from the helper: no mode is claimed.
        expectNil(HelperInstallationStatus(executablePresent: true, launchDaemonPresent: true, helper: nil).callerCheck)
        expectTrue(HelperInstallationStatus.uidOnlyWarning.contains("any process running as you"))
    }
    @Test func testStatisticsByteBoundaries() {
        expectEqual(StatisticsFormatter.bytes(0), "0 B")
        expectEqual(StatisticsFormatter.bytes(1023), "1023 B")
        expectEqual(StatisticsFormatter.bytes(1024), "1.0 KB")
        expectEqual(StatisticsFormatter.bytes(1_048_576), "1.0 MB")
        expectEqual(StatisticsFormatter.bytes(1_073_741_824), "1.0 GB")
    }
    @Test func testStatisticsRatesRejectInvalidSamples() {
        expectEqual(StatisticsFormatter.speed(-1), "0 B/s")
        expectEqual(StatisticsFormatter.speed(.nan), "0 B/s")
        expectEqual(StatisticsFormatter.speed(.infinity), "0 B/s")
        expectEqual(StatisticsFormatter.speed(2048), "2.0 KB/s")
    }
    @Test func testStatisticsDurationHandlesMissingAndFutureStart() {
        let now = Date(timeIntervalSince1970: 100000)
        expectEqual(StatisticsFormatter.duration(since: nil, now: now), "—")
        expectEqual(StatisticsFormatter.duration(since: now.addingTimeInterval(60), now: now), "00:00:00")
        expectEqual(StatisticsFormatter.duration(since: now.addingTimeInterval(-3661), now: now), "01:01:01")
        expectEqual(StatisticsFormatter.duration(since: now.addingTimeInterval(-90000), now: now), "25:00:00")
    }
    @Test func testLegacyProfileDecodesAndRoundTrips() throws {
        let json = #"[{"id":"old-id","name":"Office","host":"vpn.example.com","port":8443,"auth_type":"Saml","username":null,"realm":"staff","trusted_certs":[],"extra_args":[]}]"#
        let values = try JSONDecoder().decode([VPNProfile].self, from: Data(json.utf8))
        expectEqual(values[0].id, "old-id")
        expectEqual(try JSONDecoder().decode([VPNProfile].self, from: JSONEncoder().encode(values)), values)
        // SAML only (3.0): the old authentication fields are read past and not written back.
        let encoded = try JSONSerialization.jsonObject(with: JSONEncoder().encode(values[0])) as! [String: Any]
        expectNil(encoded["auth_type"]); expectNil(encoded["username"]); expectNil(encoded["password"])
    }
    @Test func testSettingsDefaultsMatchLegacy() throws {
        let value = try JSONDecoder().decode(AppSettings.self, from: Data(#"{"debug_mode":true}"#.utf8))
        expectTrue(value.debugMode); expectTrue(value.dnsFallback); expectFalse(value.helperDeclined)
    }
    @Test func testStorageRoundTripAndMalformedDataPreserved() throws {
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: folder) }
        let store = ConfigurationStore(directory: folder)
        expectEqual(try store.profiles(), [])
        let p = profile()
        try store.save(profiles: [p])
        expectEqual(try store.profiles(), [p])
        var settings = AppSettings(); settings.dnsFallback = false
        try store.save(settings: settings)
        expectEqual(try store.settings(), settings)
        let path = folder.appendingPathComponent("profiles.json")
        let damaged = Data("bad json".utf8)
        try damaged.write(to: path)
        expectThrows(try store.profiles())
        expectEqual(try Data(contentsOf: path), damaged)
    }
    @Test func testProfileValidationRejectsUnsafeHostAndPort() {
        for host in ["", "host;touch", "https://vpn.example.com", "../host"] {
            var p = profile(); p.host = host; expectThrows(try p.validated())
        }
        var p = profile(); p.port = 65536; expectThrows(try p.validated())
        p.port = 0; expectThrows(try p.validated())
        for host in ["010.0.0.1", "vpn-.example.com", "vpn..example.com"] {
            var p = profile(); p.host = host; expectThrows(try p.validated())
        }
        p = profile(); p.host = "192.0.2.1"; expectNoThrow(try p.validated())
    }
    @Test func testRealmIsTrimmedEmptiedOrRefused() throws {
        var p = profile(); p.realm = "  staff "
        expectEqual(try p.validated().realm, "staff")
        p.realm = "   "; expectNil(try p.validated().realm)
        p.realm = ""; expectNil(try p.validated().realm)
        // Surrounding whitespace is trimmed; anything inside the realm must be valid.
        for realm in ["sta ff", "sta\nff", "staff=1", String(repeating: "r", count: 64)] {
            p.realm = realm; expectThrows(try p.validated())
        }
    }
    @Test func testProfileTrustedCertsAreLowercased() throws {
        // The helper only accepts lowercase fingerprints; saved or pasted uppercase ones keep working.
        var p = profile(); p.trustedCerts = [String(repeating: "AB", count: 32)]
        expectEqual(try p.validated().trustedCerts, [String(repeating: "ab", count: 32)])
        expectTrue(try p.arguments().contains("--trusted-cert=" + String(repeating: "ab", count: 32)))
    }
    @Test func testArgumentsAreSAMLOnly() throws {
        var p = profile(); p.realm = "staff"
        let args = try p.arguments()
        expectTrue(args.contains("--saml-login")); expectTrue(args.contains("--realm=staff"))
        expectFalse(args.contains("-u")); expectFalse(args.contains("-p"))
    }
    @Test func testPasswordProfileFromBefore30LoadsAsSAML() throws {
        let json = #"[{"id":"old-id","name":"Office","host":"vpn.example.com","port":8443,"auth_type":"Password","username":"alice","trusted_certs":[]}]"#
        let values = try JSONDecoder().decode([VPNProfile].self, from: Data(json.utf8))
        expectEqual(try values[0].arguments(), ["vpn.example.com:8443", "--saml-login", "--set-dns=0", "--pppd-use-peerdns=0", "-v"])
        expectFalse(String(decoding: try JSONEncoder().encode(values), as: UTF8.self).contains("alice"))
    }
    /// F10: the old "Ignore certificate errors" option trusted whatever the gateway presented.
    /// A profile that still has it set loads with its explicit pins only and loses the flag on save.
    @Test func testIgnoreCertErrorsIsDecodedAndDropped() throws {
        let pin = String(repeating: "cd", count: 32)
        let json = #"[{"id":"old-id","name":"Office","host":"vpn.example.com","port":8443,"trusted_certs":["\#(pin)"],"ignore_cert_errors":true}]"#
        let values = try JSONDecoder().decode([VPNProfile].self, from: Data(json.utf8))
        expectEqual(values[0].trustedCerts, [pin])
        expectEqual(try values[0].arguments(), ["vpn.example.com:8443", "--saml-login", "--trusted-cert=" + pin, "--set-dns=0", "--pppd-use-peerdns=0", "-v"])
        expectFalse(String(decoding: try JSONEncoder().encode(values), as: UTF8.self).contains("ignore_cert_errors"))
    }
    @Test func testStoredExtraArgumentsAreDroppedOnLoad() throws {
        // Profiles written before extra arguments were removed may still carry them, including hostile ones.
        let json = #"[{"id":"old-id","name":"Office","host":"vpn.example.com","port":8443,"auth_type":"Saml","username":null,"realm":"staff","trusted_certs":[],"ignore_cert_errors":false,"extra_args":["--pppd-plugin=/tmp/x","-c/tmp/x","--persistent=5"]}]"#
        let values = try JSONDecoder().decode([VPNProfile].self, from: Data(json.utf8))
        expectEqual(values.count, 1)
        expectEqual(values[0].id, "old-id"); expectEqual(values[0].realm, "staff")
        expectNoThrow(try values[0].validated())
        expectEqual(try values[0].arguments(), ["vpn.example.com:8443", "--saml-login", "--realm=staff", "--set-dns=0", "--pppd-use-peerdns=0", "-v"])
        let encoded = try JSONEncoder().encode(values)
        expectNil((try JSONSerialization.jsonObject(with: encoded) as! [[String: Any]])[0]["extra_args"])
        expectFalse(String(decoding: encoded, as: UTF8.self).contains("pppd-plugin"))
    }
    @Test func testStoredExtraArgumentsAreGoneAfterSave() throws {
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: folder) }
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        let json = #"[{"id":"old-id","name":"Office","host":"vpn.example.com","port":8443,"auth_type":"Password","username":"alice","trusted_certs":[],"extra_args":["--pppd-log=/tmp/x"]}]"#
        try Data(json.utf8).write(to: folder.appendingPathComponent("profiles.json"))
        let store = ConfigurationStore(directory: folder)
        let loaded = try store.profiles()
        expectEqual(loaded.map(\.name), ["Office"])
        try store.save(profiles: loaded)
        let saved = try String(contentsOf: folder.appendingPathComponent("profiles.json"), encoding: .utf8)
        expectFalse(saved.contains("extra_args")); expectFalse(saved.contains("pppd-log"))
        expectEqual(try store.profiles(), loaded)
    }
    @Test func testArgumentsAreExactlyTheManagedSet() throws {
        var p = profile(); p.trustedCerts = [String(repeating: "a", count: 64)]; p.realm = "staff"
        expectEqual(try p.arguments(), ["vpn.example.com:8443", "--saml-login", "--trusted-cert=" + p.trustedCerts[0], "--realm=staff", "--set-dns=0", "--pppd-use-peerdns=0", "-v"])
        p.trustedCerts = []; p.realm = nil
        expectEqual(try p.arguments(), ["vpn.example.com:8443", "--saml-login", "--set-dns=0", "--pppd-use-peerdns=0", "-v"])
    }
    @Test func testCertificateFingerprintsValidated() throws {
        var p = profile(); p.trustedCerts = [String(repeating: "a", count: 64)]
        expectTrue(try p.arguments().contains("--trusted-cert=" + p.trustedCerts[0]))
        p.trustedCerts = ["abc"]; expectThrows(try p.validated())
    }
    @Test func testShellQuotingPreservesLiteralMetacharacters() throws {
        let value = "a'b $HOME `ignored` \"hello\""
        let result = try Commands.run("/bin/sh", ["-c", "printf '%s' " + Commands.shellQuote(value)])
        expectEqual(result.status, 0); expectEqual(result.text, value)
    }
}

private func expectEqual<T: Equatable>(_ lhs: @autoclosure () throws -> T, _ rhs: @autoclosure () throws -> T) {
    do { #expect(try lhs() == rhs()) } catch { Issue.record(error) }
}
private func expectTrue(_ value: @autoclosure () throws -> Bool) {
    do { #expect(try value()) } catch { Issue.record(error) }
}
private func expectFalse(_ value: @autoclosure () throws -> Bool) {
    do { #expect(try !value()) } catch { Issue.record(error) }
}
private func expectNil<T>(_ value: @autoclosure () throws -> T?) {
    do { #expect(try value() == nil) } catch { Issue.record(error) }
}
private func expectAtLeast<T: Comparable>(_ lhs: T, _ rhs: T) { #expect(lhs >= rhs) }
private func expectThrows<T>(_ expression: @autoclosure () throws -> T, handler: (Error) -> Void = { _ in }) {
    do { _ = try expression(); Issue.record("Expected an error") } catch { handler(error) }
}
private func expectNoThrow<T>(_ expression: @autoclosure () throws -> T) {
    do { _ = try expression() } catch { Issue.record(error) }
}
