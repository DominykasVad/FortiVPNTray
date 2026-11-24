import Testing
import Foundation
import FortiVPNShared

struct IdentityTests {
    private static let repository = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()

    @Test func testIdentityIsTheForksNotUpstreams() {
        #expect(AppIdentity.identifier == "eu.dvad.fortivpntray")
        #expect(AppIdentity.helperLabel == "eu.dvad.fortivpntray.helper")
        #expect(AppIdentity.socketPath == "/var/run/eu.dvad.fortivpntray.helper.sock")
        #expect(AppIdentity.helperLogPath == "/var/log/eu.dvad.fortivpntray.helper.log")
        #expect(AppIdentity.helperExecutablePath == "/Library/PrivilegedHelperTools/eu.dvad.fortivpntray.helper")
        #expect(AppIdentity.launchDaemonPlistPath == "/Library/LaunchDaemons/eu.dvad.fortivpntray.helper.plist")
        #expect(AppIdentity.openfortivpnDirectory == "/Library/PrivilegedHelperTools/eu.dvad.fortivpntray.helper.d")
        #expect(AppIdentity.helperSupportDirectory == "/Library/Application Support/eu.dvad.fortivpntray.helper")
        #expect(AppIdentity.helperRunDirectory == "/Library/Application Support/eu.dvad.fortivpntray.helper/run")
        #expect(AppIdentity.helperStateFile == "/Library/Application Support/eu.dvad.fortivpntray.helper/state.json")
        #expect(AppIdentity.dnsServiceKey == "State:/Network/Service/eu.dvad.fortivpntray/DNS")
    }

    @Test func testInfoPlistBundleIdentifierMatches() throws {
        let data = try Data(contentsOf: Self.repository.appendingPathComponent("native/Resources/Info.plist"))
        let plist = try #require(try PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any])
        #expect(plist["CFBundleIdentifier"] as? String == AppIdentity.identifier)
    }

    /// The helper refuses an app below `CallerRequirement.minimumClientBuild`; the app built
    /// from this tree must not be one of them.
    @Test func testInfoPlistBuildIsOneTheHelperAccepts() throws {
        let data = try Data(contentsOf: Self.repository.appendingPathComponent("native/Resources/Info.plist"))
        let plist = try #require(try PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any])
        let build = try #require((plist["CFBundleVersion"] as? String).flatMap(Int.init))
        #expect(build >= CallerRequirement.minimumClientBuild)
    }

    @Test func testNoUpstreamIdentifiersRemain() throws {
        let upstream = ["com.itstone.fortivpntray", "/var/run/fortivpntray-helper.sock", "/var/log/fortivpntray-helper.log",
                        "State:/Network/Service/FortiVPNTray/DNS", "/tmp/fortivpntray-"]
        let roots = ["native/Sources", "native/Resources", "native/scripts"]
        var checked = 0
        for root in roots {
            let files = try #require(FileManager.default.enumerator(at: Self.repository.appendingPathComponent(root), includingPropertiesForKeys: nil))
            for case let url as URL in files where ["swift", "plist", "sh"].contains(url.pathExtension) {
                let text = try String(contentsOf: url, encoding: .utf8)
                checked += 1
                for name in upstream { #expect(!text.contains(name), "\(url.lastPathComponent) still contains \(name)") }
            }
        }
        #expect(checked >= 10)
    }
}
