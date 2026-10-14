import Testing
import Foundation
import FortiVPNShared

struct IdentityTests {
    private static let repository = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    private func source(_ path: String) throws -> String {
        try String(contentsOf: Self.repository.appendingPathComponent(path), encoding: .utf8)
    }

    @Test func testIdentityIsTheForksNotUpstreams() {
        #expect(AppIdentity.identifier == "eu.dvad.fortivpntray")
        #expect(AppIdentity.helperLabel == "eu.dvad.fortivpntray.helper")
        #expect(AppIdentity.socketPath == "/var/run/eu.dvad.fortivpntray.helper.sock")
        #expect(AppIdentity.helperLogPath == "/var/log/eu.dvad.fortivpntray.helper.log")
        #expect(AppIdentity.helperExecutablePath == "/Library/PrivilegedHelperTools/eu.dvad.fortivpntray.helper")
        #expect(AppIdentity.launchDaemonPlistPath == "/Library/LaunchDaemons/eu.dvad.fortivpntray.helper.plist")
        #expect(AppIdentity.openfortivpnDirectory == "/Library/PrivilegedHelperTools/eu.dvad.fortivpntray.helper.d")
        #expect(AppIdentity.helperRunDirectory == "/Library/Application Support/eu.dvad.fortivpntray.helper/run")
        #expect(AppIdentity.dnsServiceKey == "State:/Network/Service/eu.dvad.fortivpntray/DNS")
        #expect(AppIdentity.sessionLogPrefix == "/tmp/eu.dvad.fortivpntray-")
    }

    @Test func testInfoPlistBundleIdentifierMatches() throws {
        let data = try Data(contentsOf: Self.repository.appendingPathComponent("native/Resources/Info.plist"))
        let plist = try #require(try PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any])
        #expect(plist["CFBundleIdentifier"] as? String == AppIdentity.identifier)
    }

    @Test func testRustHelperUsesTheSameNames() throws {
        #expect(try source("helper/src/server.rs").contains("SOCKET_PATH: &str = \"\(AppIdentity.socketPath)\""))
        #expect(try source("helper/src/validation.rs").contains("s.starts_with(\"\(AppIdentity.sessionLogPrefix)\")"))
        let handlers = try source("helper/src/handlers.rs")
        #expect(handlers.contains("set \(AppIdentity.dnsServiceKey)\\n"))
        #expect(handlers.contains("remove \(AppIdentity.dnsServiceKey)\\n"))
    }

    @Test func testNoUpstreamIdentifiersRemain() throws {
        let upstream = ["com.itstone.fortivpntray", "/var/run/fortivpntray-helper.sock", "/var/log/fortivpntray-helper.log",
                        "State:/Network/Service/FortiVPNTray/DNS", "/tmp/fortivpntray-"]
        let roots = ["native/Sources", "native/Resources", "native/scripts", "helper/src"]
        var checked = 0
        for root in roots {
            let files = try #require(FileManager.default.enumerator(at: Self.repository.appendingPathComponent(root), includingPropertiesForKeys: nil))
            for case let url as URL in files where ["swift", "rs", "plist", "sh"].contains(url.pathExtension) {
                let text = try String(contentsOf: url, encoding: .utf8)
                checked += 1
                for name in upstream { #expect(!text.contains(name), "\(url.lastPathComponent) still contains \(name)") }
            }
        }
        #expect(checked >= 10)
    }
}
