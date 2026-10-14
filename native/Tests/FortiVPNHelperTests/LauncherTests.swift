import Testing
import Foundation
import FortiVPNShared
@testable import FortiVPNHelper

/// The config writer, argv, environment, and the launcher against a fake openfortivpn.
struct LauncherTests {
    private let cert = String(repeating: "0123456789abcdef", count: 4)

    /// Every key openfortivpn 1.24.1's `load_config` knows (`config.c`).
    private static let knownKeys: Set<String> = [
        "host", "port", "username", "password", "otp", "otp-prompt", "otp-delay", "cookie", "cookie-on-stdin",
        "no-ftm-push", "pinentry", "realm", "set-dns", "sni", "set-routes", "half-internet-routes", "persistent",
        "pppd-use-peerdns", "pppd-log", "pppd-plugin", "pppd-ipparam", "pppd-ifname", "pppd-call", "pppd-accept-remote",
        "pppd", "ppp-system", "use-resolvconf", "use-syslog", "trusted-cert", "ca-file", "user-cert", "saml-login",
        "user-key", "pem-passphrase", "insecure-ssl", "cipher-list", "min-tls", "seclevel-1", "user-agent", "hostcheck",
        "check-virtual-desktop",
    ]

    /// Reads a config file the way openfortivpn's `load_config` does: lines shorter
    /// than two bytes and lines starting with `#` are skipped, the key ends at the
    /// first `=`, and whitespace is trimmed from both sides of key and value.
    private func parse(_ text: String) -> [(String, String)] {
        text.split(separator: "\n", omittingEmptySubsequences: false).compactMap { line in
            guard line.utf8.count + 1 >= 2, !line.hasPrefix("#"), let equals = line.firstIndex(of: "=") else { return nil }
            let key = line[..<equals].trimmingCharacters(in: .whitespaces)
            let value = line[line.index(after: equals)...].trimmingCharacters(in: .whitespaces)
            return (key, value)
        }
    }

    private func failure(_ body: () throws -> Void) -> String? {
        do { try body(); return nil } catch { return String(describing: error) }
    }

    // MARK: Config file

    @Test func testConfigOrderAndContent() throws {
        let request = try ConnectRequest(host: "vpn.example.com", port: 8443, realm: "staff",
                                         auth: .saml(listenPort: 8021), trustedCerts: [cert, String(cert.reversed())])
        #expect(try OpenFortiVPNConfig.render(request) == """
            set-dns = 0
            pppd-use-peerdns = 0
            host = vpn.example.com
            port = 8443
            saml-login = 8021
            realm = staff
            trusted-cert = \(cert)
            trusted-cert = \(String(cert.reversed()))

            """)
        let minimal = try ConnectRequest(host: "192.0.2.1", port: 443)
        #expect(try OpenFortiVPNConfig.render(minimal) == "set-dns = 0\npppd-use-peerdns = 0\nhost = 192.0.2.1\nport = 443\nsaml-login = 8020\n")
    }

    @Test func testWrittenConfigParsesBackWithEveryKey() throws {
        let request = try ConnectRequest(host: "vpn.example.com", port: 10443, realm: "Staff_2.example-x",
                                         auth: .saml(listenPort: 65535), trustedCerts: Array(repeating: cert, count: 16))
        let fake = try FakeInstall()
        try fake.runDirectory.prepare()
        let path = try fake.runDirectory.create("parse.conf", contents: Data(try OpenFortiVPNConfig.render(request).utf8))
        let parsed = parse(try String(contentsOfFile: path, encoding: .utf8))
        let expected = [("set-dns", "0"), ("pppd-use-peerdns", "0"), ("host", "vpn.example.com"), ("port", "10443"),
                        ("saml-login", "65535"), ("realm", "Staff_2.example-x")] + Array(repeating: ("trusted-cert", cert), count: 16)
        #expect(parsed.map(\.0) == expected.map(\.0))
        #expect(parsed.map(\.1) == expected.map(\.1))
        // An unknown key would make openfortivpn drop the rest of the file (S3).
        #expect(parsed.allSatisfy { Self.knownKeys.contains($0.0) })
        #expect(Set(OpenFortiVPNConfig.keys).isSubset(of: Self.knownKeys))
    }

    @Test func testConfigLinesRefuseAnythingTheParserWouldReadDifferently() throws {
        for value in ["", "a\nb", "a\rb", "a\0b", "a=b", "=", "a b", " a", "a ", "a\tb", "é", "a\u{7f}"] {
            #expect(failure { _ = try OpenFortiVPNConfig.line("host", value) } == "Refusing to write config key host.", "\(value.debugDescription)")
        }
        for key in ["pppd-plugin", "ca-file", "insecure-ssl", "Host", ""] {
            #expect(failure { _ = try OpenFortiVPNConfig.line(key, "x") } != nil, "\(key)")
        }
        #expect(try OpenFortiVPNConfig.line("realm", "a.b_c-D") == "realm = a.b_c-D\n")
    }

    // MARK: argv and environment

    @Test func testArgumentsAreFixed() {
        #expect(OpenFortiVPNLauncher.arguments(configPath: "/Library/Application Support/x/run/a.conf")
                == ["-c", "/Library/Application Support/x/run/a.conf", "-v"])
    }

    @Test func testEnvironmentIsExactlyThePinnedOne() {
        #expect(OpenFortiVPNLauncher.environment(for: .production) == [
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "OPENSSL_CONF": "/dev/null",
            "OPENSSL_MODULES": "/Library/PrivilegedHelperTools/eu.dvad.fortivpntray.helper.d/lib/ossl-modules",
            "SSL_CERT_FILE": "/etc/ssl/cert.pem",
            "SSL_CERT_DIR": "/Library/PrivilegedHelperTools/eu.dvad.fortivpntray.helper.d/certs",
        ])
    }

    // MARK: Launcher with a fake openfortivpn

    private final class Events: @unchecked Sendable {
        // @unchecked Sendable: `_all` is only touched while holding `lock`.
        private let lock = NSLock()
        private var _all: [TunnelEvent] = []
        var all: [TunnelEvent] { lock.withLock { _all } }
        func record(_ event: TunnelEvent) { lock.withLock { _all.append(event) } }
    }

    @Test func testChildGetsFixedArgvEnvironmentAndConfigAndConfigIsDeletedWhenUp() throws {
        let fake = try FakeInstall()
        let launcher = OpenFortiVPNLauncher(install: fake.install, runDirectory: fake.runDirectory)
        let events = Events()
        let id = UUID().uuidString
        let request = try ConnectRequest(host: "vpn.example.com", port: 8443, realm: "staff", trustedCerts: [cert])
        try launcher.start(request, sessionID: id) { events.record($0) }
        defer { launcher.stop(sessionID: id) }

        let report = try #require(fake.waitForReport())
        let configPath = fake.runDirectory.path + "/\(id).conf"
        #expect(report.filter { $0.hasPrefix("arg:") } == ["arg:-c", "arg:" + configPath, "arg:-v"])
        // The shell adds PWD, SHLVL and _ itself; everything else came from the launcher.
        let environment = report.filter { $0.hasPrefix("env:") && !["env:PWD=", "env:SHLVL=", "env:_="].contains(where: $0.hasPrefix) }
        #expect(environment == OpenFortiVPNLauncher.environment(for: fake.install).map { "env:\($0)=\($1)" }.sorted())
        #expect(report.contains("env:PWD=/"))
        let config = report.drop(while: { $0 != "config:" }).dropFirst().joined(separator: "\n")
        #expect(config == (try OpenFortiVPNConfig.render(request)))

        #expect(eventually { events.all.contains(.tunnelUp) })
        #expect(Array(events.all.prefix(3)) == [.output("INFO:   Connected to gateway."), .output("INFO:   Tunnel is up and running."), .tunnelUp])
        #expect(fake.configFiles().isEmpty, "the config file is deleted once the tunnel is up")
    }

    @Test func testStopEndsTheChildWithSIGINT() throws {
        let fake = try FakeInstall()
        let pid = Box<pid_t>()
        let launcher = OpenFortiVPNLauncher(install: fake.install, runDirectory: fake.runDirectory, spawned: { pid.value = $0 })
        let events = Events()
        let id = UUID().uuidString
        try launcher.start(try ConnectRequest(host: "vpn.example.com", port: 443), sessionID: id) { events.record($0) }
        let child = try #require(pid.value)
        #expect(fake.waitForReport() != nil)
        #expect(isAlive(child))
        launcher.stop(sessionID: id)
        #expect(!isAlive(child))
        #expect(eventually { events.all.last == .exited(.signal(SIGINT)) })
        #expect(fake.configFiles().isEmpty)
        // A new session can start once the old child is gone.
        let next = UUID().uuidString
        try launcher.start(try ConnectRequest(host: "vpn.example.com", port: 443), sessionID: next) { _ in }
        launcher.stop(sessionID: next)
    }

    @Test func testStopEscalatesToSIGKILL() throws {
        let fake = try FakeInstall(script: FakeInstall.script(then: "trap '' INT\nexec /bin/sleep 30"))
        let pid = Box<pid_t>()
        let launcher = OpenFortiVPNLauncher(install: fake.install, runDirectory: fake.runDirectory, spawned: { pid.value = $0 })
        let events = Events()
        let id = UUID().uuidString
        try launcher.start(try ConnectRequest(host: "vpn.example.com", port: 443), sessionID: id) { events.record($0) }
        #expect(fake.waitForReport() != nil)
        let began = Date()
        launcher.stop(sessionID: id)
        #expect(Date().timeIntervalSince(began) >= OpenFortiVPNLauncher.stopGrace - 0.1)
        #expect(!isAlive(try #require(pid.value)))
        #expect(eventually { events.all.last == .exited(.signal(SIGKILL)) })
    }

    @Test func testStopIgnoresOtherSessions() throws {
        let fake = try FakeInstall()
        let pid = Box<pid_t>()
        let launcher = OpenFortiVPNLauncher(install: fake.install, runDirectory: fake.runDirectory, spawned: { pid.value = $0 })
        let id = UUID().uuidString
        try launcher.start(try ConnectRequest(host: "vpn.example.com", port: 443), sessionID: id) { _ in }
        launcher.stop(sessionID: UUID().uuidString)
        #expect(isAlive(try #require(pid.value)))
        #expect(failure { try launcher.start(try ConnectRequest(host: "vpn.example.com", port: 443), sessionID: UUID().uuidString) { _ in } }
                == "openfortivpn is already running.")
        launcher.stop(sessionID: id)
    }

    @Test func testChildExitIsReportedAndConfigDeleted() throws {
        let fake = try FakeInstall(script: FakeInstall.script(then: "exit 3"))
        let launcher = OpenFortiVPNLauncher(install: fake.install, runDirectory: fake.runDirectory)
        let events = Events()
        try launcher.start(try ConnectRequest(host: "vpn.example.com", port: 443), sessionID: UUID().uuidString) { events.record($0) }
        #expect(eventually { events.all.last == .exited(.status(3)) })
        #expect(fake.configFiles().isEmpty)
        // The launcher forgot the dead child, so the next start is allowed.
        let next = UUID().uuidString
        try launcher.start(try ConnectRequest(host: "vpn.example.com", port: 443), sessionID: next) { _ in }
        #expect(eventually { fake.configFiles().isEmpty })
        launcher.stop(sessionID: next)
    }

    @Test func testNothingIsSpawnedOrWrittenWhenTheInstallFailsItsCheck() throws {
        let fake = try FakeInstall()
        try fake.write("tampered", to: fake.install.libraryDirectory + "/libssl.4.dylib", mode: 0o644)
        let launcher = OpenFortiVPNLauncher(install: fake.install, runDirectory: fake.runDirectory, spawned: { _ in Issue.record("spawned") })
        #expect(failure { try launcher.start(try ConnectRequest(host: "vpn.example.com", port: 443), sessionID: UUID().uuidString) { _ in } }
                == "lib/libssl.4.dylib does not match the manifest")
        #expect(fake.waitForReport(timeout: 0.2) == nil)
        #expect(fake.configFiles().isEmpty)
        #expect(failure { try launcher.start(try ConnectRequest(host: "vpn.example.com", port: 443), sessionID: "../../x") { _ in } }
                == "Bad session id.")
    }

    /// The review case with a real child: disconnect arrives after the child was
    /// spawned and before the launcher recorded its PID. The controller defers the
    /// stop until start() returns, and the child does not survive.
    @Test func testDisconnectBeforeThePIDIsRecordedLeavesNoChild() throws {
        let fake = try FakeInstall()
        let pid = Box<pid_t>()
        let spawned = DispatchSemaphore(value: 0)
        let release = DispatchSemaphore(value: 0)
        let launcher = OpenFortiVPNLauncher(install: fake.install, runDirectory: fake.runDirectory, spawned: {
            pid.value = $0
            spawned.signal()
            _ = release.wait(timeout: .now() + 10)
        })
        let sessions = SessionController(launcher: launcher)
        let request = try ConnectRequest(host: "vpn.example.com", port: 443)
        let connect = onThread { SessionControllerTests.attempt { try sessions.connect(request) } }
        #expect(spawned.wait(timeout: .now() + 10) == .success)
        let child = try #require(pid.value)
        #expect(isAlive(child))

        sessions.disconnect()
        #expect(sessions.status().state == .disconnecting)
        #expect(isAlive(child), "nothing is stopped while start() is still running")

        release.signal()
        #expect(try #require(connect()) == .failure(SessionController.Refusal(description: SessionController.disconnectedWhileStarting)))
        #expect(!isAlive(child))
        #expect(sessions.status() == HelperStatus())
        #expect(fake.configFiles().isEmpty)
    }

    /// A real child whose last lines arrive after its exit: a background job keeps the
    /// pipe open and writes once the child is gone, and the final line has no newline.
    /// `readLog` of the last session shows them, redacted.
    @Test func testTheChildsFinalLinesReachTheLastSessionsLog() throws {
        let fake = try FakeInstall(script: FakeInstall.script(then: """
        /bin/sleep 1
        echo 'DEBUG:  Cookie: SVPNCOOKIE=4f1d0c9a8b7e6d5c4b3a2918'
        echo 'ERROR:  Could not authenticate to gateway.'
        ( /bin/sleep 1; echo 'INFO:   Closed connection to gateway.'; printf 'INFO:   Logged out.' ) &
        exit 1
        """))
        let sessions = SessionController(launcher: OpenFortiVPNLauncher(install: fake.install, runDirectory: fake.runDirectory))
        // The child waits a second before failing, so connect returns the id first.
        let id = try sessions.connect(try ConnectRequest(host: "vpn.example.com", port: 443))
        #expect(eventually { sessions.status() == HelperStatus(lastError: "openfortivpn exited with status 1.") })
        #expect(try sessions.readLog(sessionID: id, offset: 0).lines.contains("INFO:   Logged out.") == false,
                "the background job has not written yet when the exit is seen")
        let expected = [
            "INFO:   Connected to gateway.",
            "DEBUG:  Cookie: [redacted]",
            "ERROR:  Could not authenticate to gateway.",
            "INFO:   Closed connection to gateway.",
            "INFO:   Logged out.",
        ]
        #expect(eventually { (try? sessions.readLog(sessionID: id, offset: 0).lines) == expected },
                "\(String(describing: try? sessions.readLog(sessionID: id, offset: 0).lines))")
    }

    @Test func testPendingSAMLURLFromARealChild() throws {
        let fake = try FakeInstall(script: FakeInstall.script(then: """
        echo "INFO:   Authenticate at 'https://vpn.example.com:10443/remote/saml/start?redirect=1&realm=staff'"
        exec /bin/sleep 30
        """))
        let launcher = OpenFortiVPNLauncher(install: fake.install, runDirectory: fake.runDirectory)
        let sessions = SessionController(launcher: launcher)
        let id = try sessions.connect(try ConnectRequest(host: "vpn.example.com", port: 10443, realm: "staff"))
        #expect(eventually { sessions.pendingSAMLURL() == URL(string: "https://vpn.example.com:10443/remote/saml/start?redirect=1&realm=staff") })
        #expect(try sessions.readLog(sessionID: id, offset: 0).lines.last == "INFO:   Authenticate at '[redacted]")
        sessions.disconnect()
        #expect(sessions.pendingSAMLURL() == nil)
    }

    @Test func testLineSplitter() {
        let lines = Box<[String]>()
        lines.value = []
        let splitter = LineSplitter { line in lines.value = (lines.value ?? []) + [line] }
        splitter.append(Data("one\ntw".utf8))
        splitter.append(Data("o\n\nthree".utf8))
        #expect(lines.value == ["one", "two", ""])
        splitter.finish()
        #expect(lines.value == ["one", "two", "", "three"])
        lines.value = []
        splitter.append(Data(repeating: UInt8(ascii: "x"), count: LineSplitter.maxLineLength + 10))
        #expect(lines.value?.map(\.count) == [LineSplitter.maxLineLength])
    }
}
