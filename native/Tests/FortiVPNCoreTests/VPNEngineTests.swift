import Testing
import Foundation
import FortiVPNShared
@testable import FortiVPNCore

/// A helper whose answers the test sets; it records what the engine asked.
final class FakeHelperAPI: HelperAPI, @unchecked Sendable {
    // @unchecked Sendable: every field is only touched while holding `lock`.
    private let lock = NSLock()
    private var _requests: [ConnectRequest] = []
    private var _disconnects = 0
    private var _logReads: [Int] = []
    var protocolVersion = HelperTransport.protocolVersion
    var connectError: String?
    var currentStatus = HelperStatus()
    var log: [String] = []
    var samlURL: URL?
    let sessionID = UUID().uuidString

    var requests: [ConnectRequest] { lock.withLock { _requests } }
    var disconnects: Int { lock.withLock { _disconnects } }
    var logReads: [Int] { lock.withLock { _logReads } }

    func set(_ change: (FakeHelperAPI) -> Void) { lock.withLock { change(self) } }

    func version() throws -> HelperVersion {
        lock.withLock { HelperVersion(version: "0.3.0", protocolVersion: protocolVersion, mode: .signed) }
    }
    func status() throws -> HelperStatus { lock.withLock { currentStatus } }
    func connect(_ request: ConnectRequest) throws -> String {
        try lock.withLock {
            _requests.append(request)
            if let connectError { throw VPNError(connectError) }
            currentStatus = HelperStatus(state: .connecting, sessionID: sessionID)
            return sessionID
        }
    }
    func disconnect() throws {
        lock.withLock {
            _disconnects += 1
            currentStatus = HelperStatus()
        }
    }
    func readLog(sessionID: String, offset: Int) throws -> LogChunk {
        try lock.withLock {
            _logReads.append(offset)
            guard sessionID == self.sessionID else { throw VPNError("Unknown session.") }
            // Two lines at most per read, to exercise reading on.
            let lines = Array(log.dropFirst(offset).prefix(2))
            return LogChunk(lines: lines, nextOffset: min(log.count, offset + lines.count))
        }
    }
    func pendingSAMLURL() throws -> URL? { lock.withLock { samlURL } }
}

struct VPNEngineTests {
    private func profile(realm: String? = nil) -> VPNProfile {
        var p = VPNProfile()
        p.name = "Office"; p.host = "vpn.example.com"; p.port = 10443; p.realm = realm
        p.trustedCerts = [String(repeating: "AB", count: 32)]
        return p
    }

    @Test func testStartSendsTheValidatedRequest() async throws {
        let helper = FakeHelperAPI()
        let engine = VPNEngine(helper: helper)
        var settings = AppSettings(); settings.dnsFallback = false
        try await engine.start(profile: profile(realm: " staff "), settings: settings)
        #expect(helper.requests == [try ConnectRequest(host: "vpn.example.com", port: 10443, realm: "staff",
                                                       trustedCerts: [String(repeating: "ab", count: 32)], useSystemDNSFallback: false)])
        #expect(await engine.hasSession)
        await #expect(throws: VPNError("Disconnect the current session before reconnecting.")) {
            try await engine.start(profile: profile(), settings: AppSettings())
        }
    }

    @Test func testStartRefusesAnotherProtocolOrAFailedConnect() async throws {
        let old = FakeHelperAPI()
        old.set { $0.protocolVersion = HelperTransport.protocolVersion + 1 }
        let engine = VPNEngine(helper: old)
        await #expect(throws: VPNError.self) { try await engine.start(profile: profile(), settings: AppSettings()) }
        #expect(old.requests.isEmpty)

        let refusing = FakeHelperAPI()
        refusing.set { $0.connectError = "A session is already active." }
        let second = VPNEngine(helper: refusing)
        await #expect(throws: VPNError("A session is already active.")) { try await second.start(profile: profile(), settings: AppSettings()) }
        #expect(await !second.hasSession)
    }

    @Test func testPollReadsTheLogOnAndReportsConnectedOnce() async throws {
        let helper = FakeHelperAPI()
        let engine = VPNEngine(helper: helper)
        try await engine.start(profile: profile(), settings: AppSettings())
        helper.set { $0.log = ["INFO:   Connected to gateway.", "DEBUG:  Cookie: [redacted]", "INFO:   Tunnel is up and running."] }
        let first = try await engine.poll()
        #expect(first.lines == ["INFO:   Connected to gateway.", "DEBUG:  Cookie: [redacted]"])
        #expect(first.events.isEmpty, "the log line alone does not make the session connected")
        helper.set { $0.currentStatus = HelperStatus(state: .connected, sessionID: helper.sessionID, interface: "ppp0", vpnIP: "192.0.2.200") }
        let second = try await engine.poll()
        #expect(second.lines == ["INFO:   Tunnel is up and running."])
        #expect(second.events == [.connected("192.0.2.200")])
        #expect(try await engine.poll().events.isEmpty)
        #expect(helper.logReads == [0, 2, 3])
    }

    @Test func testSAMLURLIsOpenedOnlyIfItIsTheProfilesLoginURL() async throws {
        let helper = FakeHelperAPI()
        let engine = VPNEngine(helper: helper)
        try await engine.start(profile: profile(), settings: AppSettings())
        let good = URL(string: "https://vpn.example.com:10443/remote/saml/start?redirect=1")!
        helper.set { $0.samlURL = good }
        #expect(try await engine.poll().events == [.saml(good)])
        #expect(try await engine.poll().events.isEmpty, "opened once")

        let bad = URL(string: "https://attacker.example.net:10443/remote/saml/start?redirect=1")!
        helper.set { $0.samlURL = bad }
        let refused = try await engine.poll()
        #expect(refused.events.isEmpty)
        #expect(refused.lines == ["ERROR:  The helper offered an unexpected login URL; it was not opened."])
    }

    @Test func testSAMLLoginCheck() {
        let host = "vpn.example.com", port = 10443
        for good in ["https://vpn.example.com:10443/remote/saml/start?redirect=1",
                     "https://VPN.example.com:10443/remote/saml/start?redirect=1&realm=staff"] {
            #expect(SAMLLogin.isExpected(URL(string: good)!, host: host, port: port), "\(good)")
        }
        for bad in ["http://vpn.example.com:10443/remote/saml/start?redirect=1",
                    "https://vpn.example.com/remote/saml/start?redirect=1",
                    "https://vpn.example.com:443/remote/saml/start?redirect=1",
                    "https://vpn.example.com.attacker.example:10443/remote/saml/start",
                    "https://attacker.example@vpn.example.com:10443/remote/saml/start",
                    "https://vpn.example.com:10443/remote/saml/start/../../evil",
                    "https://vpn.example.com:10443/remote/logout",
                    "https://vpn.example.com:10443/remote/saml/start#x",
                    "file:///remote/saml/start"] {
            #expect(!SAMLLogin.isExpected(URL(string: bad)!, host: host, port: port), "\(bad)")
        }
    }

    @Test func testCertificateDigestFromTheLogBecomesAnEvent() async throws {
        let helper = FakeHelperAPI()
        let engine = VPNEngine(helper: helper)
        try await engine.start(profile: profile(), settings: AppSettings())
        let digest = String(repeating: "cd", count: 32)
        helper.set { $0.log = ["ERROR:  Gateway certificate validation failed, and the certificate digest is not in the local whitelist.",
                               "ERROR:      --trusted-cert \(digest)"] }
        #expect(try await engine.poll().events == [.certificate(digest)])
    }

    /// The session ended in the helper: the rest of its log is read before the end is reported.
    @Test func testEndOfSessionDrainsTheLogAndReportsWhy() async throws {
        let helper = FakeHelperAPI()
        let engine = VPNEngine(helper: helper)
        try await engine.start(profile: profile(), settings: AppSettings())
        helper.set {
            $0.log = ["a", "b", "c", "d", "ERROR:  Could not authenticate to gateway."]
            $0.currentStatus = HelperStatus(lastError: "openfortivpn exited with status 1.")
        }
        let result = try await engine.poll()
        #expect(result.lines == ["a", "b", "c", "d", "ERROR:  Could not authenticate to gateway."])
        #expect(result.exitMessage == "openfortivpn exited with status 1.")
        #expect(await !engine.hasSession)
        #expect(try await engine.poll().lines.isEmpty)
    }

    @Test func testEndWithoutAnErrorAfterConnecting() async throws {
        let helper = FakeHelperAPI()
        let engine = VPNEngine(helper: helper)
        try await engine.start(profile: profile(), settings: AppSettings())
        helper.set { $0.currentStatus = HelperStatus(state: .connected, sessionID: helper.sessionID) }
        _ = try await engine.poll()
        helper.set { $0.currentStatus = HelperStatus() }
        #expect(try await engine.poll().exitMessage == "The VPN connection ended.")
    }

    @Test func testStopDisconnectsOnlyWithASession() async throws {
        let helper = FakeHelperAPI()
        let engine = VPNEngine(helper: helper)
        try await engine.stop()
        #expect(helper.disconnects == 0)
        try await engine.start(profile: profile(), settings: AppSettings())
        try await engine.stop()
        #expect(helper.disconnects == 1)
        #expect(await !engine.hasSession)
    }

    @Test func testInterfaceBytesOnlyForPPPNames() {
        let wifi = VPNEngine.interfaceBytes("en0")
        #expect(wifi.0 == 0 && wifi.1 == 0, "not a tunnel interface: never read")
        let none = VPNEngine.interfaceBytes("en0; rm")
        #expect(none.0 == 0 && none.1 == 0)
        let missing = VPNEngine.interfaceBytes("ppp987")
        #expect(missing.0 == 0 && missing.1 == 0)
    }
}
