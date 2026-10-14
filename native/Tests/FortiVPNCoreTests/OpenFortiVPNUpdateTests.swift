import Testing
import Foundation
import CryptoKit
import FortiVPNShared
@testable import FortiVPNCore

/// The openfortivpn update check (PLAN.md 3.4) on a made-up Homebrew tree: opt/ links
/// into Cellar/, like Homebrew, and an `otool -L` stand-in.
struct OpenFortiVPNUpdateTests {
    final class Tree {
        let root: String
        var brew: String { root + "/homebrew" }
        var binaryLink: String { brew + "/bin/openfortivpn" }
        var manifest: String { root + "/manifest.json" }
        var keg = "1.24.1_1"
        var openssl = "4.0.3"

        init() throws {
            let temporary = FileManager.default.temporaryDirectory.appendingPathComponent("fvt-update-" + UUID().uuidString)
            try FileManager.default.createDirectory(at: temporary, withIntermediateDirectories: false)
            root = try OpenFortiVPNUpdateCheck.realPath(temporary.path)
            try install()
        }

        deinit { try? FileManager.default.removeItem(atPath: root) }

        var binaryReal: String { brew + "/Cellar/openfortivpn/\(keg)/bin/openfortivpn" }
        func libraryReal(_ name: String) -> String { brew + "/Cellar/openssl@4/\(openssl)/lib/\(name)" }
        func libraryLink(_ name: String) -> String { brew + "/opt/openssl@4/lib/\(name)" }

        /// (Re)creates the Cellar kegs and the links, as `brew install` / `brew upgrade` would.
        func install(crypto: String = "crypto", ssl: String = "ssl") throws {
            let files = FileManager.default
            for directory in [brew + "/bin", brew + "/opt", (binaryReal as NSString).deletingLastPathComponent, (libraryReal("x") as NSString).deletingLastPathComponent] {
                try files.createDirectory(atPath: directory, withIntermediateDirectories: true)
            }
            try Data("openfortivpn \(keg)".utf8).write(to: URL(fileURLWithPath: binaryReal))
            try (Data("\u{0}\(crypto)\u{0}OpenSSL \(openssl) 29 Sep 2026\u{0}".utf8)).write(to: URL(fileURLWithPath: libraryReal("libcrypto.4.dylib")))
            try Data(ssl.utf8).write(to: URL(fileURLWithPath: libraryReal("libssl.4.dylib")))
            for link in [binaryLink, brew + "/opt/openssl@4"] { try? files.removeItem(atPath: link) }
            try files.createSymbolicLink(atPath: binaryLink, withDestinationPath: binaryReal)
            try files.createSymbolicLink(atPath: brew + "/opt/openssl@4", withDestinationPath: brew + "/Cellar/openssl@4/\(openssl)")
        }

        /// What `otool -L` lists after its first line: a library's own install name first.
        func libraries(_ path: String) throws -> [String] {
            switch (path as NSString).lastPathComponent {
            case "openfortivpn": return [libraryLink("libssl.4.dylib"), libraryLink("libcrypto.4.dylib"), "/usr/lib/libutil.dylib", "/usr/lib/libSystem.B.dylib"]
            case "libssl.4.dylib": return [libraryLink("libssl.4.dylib"), libraryLink("libcrypto.4.dylib"), "/usr/lib/libSystem.B.dylib"]
            case "libcrypto.4.dylib": return [libraryLink("libcrypto.4.dylib"), "/usr/lib/libSystem.B.dylib"]
            default: return []
            }
        }

        /// The manifest the installer writes for the files as they are now. The source set
        /// hash is spelled out here as `HelperInstallScript` computes it: the binary, then
        /// lib/ sorted by name; "<sha256 of the original>  <its real path>" per file.
        func writeManifest() throws {
            func hash(_ path: String) throws -> String {
                SHA256.hash(data: try Data(contentsOf: URL(fileURLWithPath: path))).map { String(format: "%02x", $0) }.joined()
            }
            let lines = try [binaryReal, libraryReal("libcrypto.4.dylib"), libraryReal("libssl.4.dylib")].map { "\(try hash($0))  \($0)\n" }.joined()
            let set = SHA256.hash(data: Data(lines.utf8)).map { String(format: "%02x", $0) }.joined()
            let json = """
            {"openfortivpn_version": "\(keg.split(separator: "_")[0])", "openssl_version": "OpenSSL \(openssl) 29 Sep 2026", "homebrew_keg": "\(keg)",
             "set_sha256": "\(String(repeating: "0", count: 64))", "source_set_sha256": "\(set)", "files": []}
            """
            try Data(json.utf8).write(to: URL(fileURLWithPath: manifest))
        }

        func check() -> OpenFortiVPNUpdateStatus {
            OpenFortiVPNUpdateCheck.check(manifest: manifest, homebrewBinary: binaryLink, libraries: libraries)
        }
    }

    @Test func testSameFilesAreUpToDate() throws {
        let tree = try Tree()
        try tree.writeManifest()
        let status = tree.check()
        #expect(status.state == .upToDate)
        #expect(status.installed == OpenFortiVPNVersions(openfortivpn: "1.24.1", openssl: "OpenSSL 4.0.3 29 Sep 2026"))
        #expect(status.homebrew == status.installed)
    }

    /// The case the plan names: OpenSSL changes while openfortivpn's version does not.
    @Test func testAChangedOpenSSLIsAnUpdate() throws {
        let tree = try Tree()
        try tree.writeManifest()
        tree.openssl = "4.0.4"
        try tree.install()
        let status = tree.check()
        #expect(status.state == .updateAvailable)
        #expect(status.installed?.openfortivpn == status.homebrew?.openfortivpn)
        #expect(status.homebrew?.openssl == "OpenSSL 4.0.4 29 Sep 2026")
        #expect(status.detail == "Installed: openfortivpn 1.24.1 · OpenSSL 4.0.3 29 Sep 2026\nHomebrew: openfortivpn 1.24.1 · OpenSSL 4.0.4 29 Sep 2026")
    }

    @Test func testAChangedFileWithTheSameVersionsIsAnUpdate() throws {
        let tree = try Tree()
        try tree.writeManifest()
        try tree.install(ssl: "rebuilt ssl")
        #expect(tree.check().state == .updateAvailable)
    }

    @Test func testANewOpenFortiVPNKegIsAnUpdate() throws {
        let tree = try Tree()
        try tree.writeManifest()
        tree.keg = "1.25.0"
        try tree.install()
        let status = tree.check()
        #expect(status.state == .updateAvailable)
        #expect(status.homebrew?.openfortivpn == "1.25.0")
    }

    @Test func testMissingPieces() throws {
        let tree = try Tree()
        #expect(tree.check().state == .notInstalled, "no manifest: no copy")
        try tree.writeManifest()
        try FileManager.default.removeItem(atPath: tree.binaryLink)
        let missing = tree.check()
        #expect(missing.state == .homebrewMissing)
        #expect(missing.installed?.openfortivpn == "1.24.1", "the working copy is still shown")

        let garbage = try Tree()
        try Data("{\"source_set_sha256\": \"short\"}".utf8).write(to: URL(fileURLWithPath: garbage.manifest))
        #expect(garbage.check().state == .unknown("the installed copy's manifest cannot be read. Repair the helper."))
    }

    @Test func testWhatTheInstallerWouldRefuseIsNotCompared() throws {
        let rpath = try Tree()
        try rpath.writeManifest()
        let status = OpenFortiVPNUpdateCheck.check(manifest: rpath.manifest, homebrewBinary: rpath.binaryLink) { path in
            (path as NSString).lastPathComponent == "openfortivpn" ? ["@rpath/libssl.4.dylib"] : []
        }
        guard case .unknown = status.state else { Issue.record("\(status.state)"); return }

        let clash = try Tree()
        try clash.writeManifest()
        let other = clash.brew + "/Cellar/other/1/lib/libssl.4.dylib"
        try FileManager.default.createDirectory(atPath: (other as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
        try Data("other".utf8).write(to: URL(fileURLWithPath: other))
        let clashing = OpenFortiVPNUpdateCheck.check(manifest: clash.manifest, homebrewBinary: clash.binaryLink) { path in
            (path as NSString).lastPathComponent == "openfortivpn" ? [clash.libraryLink("libssl.4.dylib"), other] : []
        }
        #expect(clashing.state == .unknown("two different libraries are both called libssl.4.dylib."))
    }

    /// The check mirrors the installer; if the installer's source-set lines or file order
    /// change, this fails and the check must follow.
    @Test func testTheInstallerStillHashesTheSourceSetThisWay() throws {
        let script = try HelperInstallScript.install(arguments: try HelperLaunchArguments(allowedUID: 501, callerCheck: .uidOnly),
                                                     bundledHelper: "/Applications/FortiVPNTray.app/Contents/Resources/FortiVPNHelper",
                                                     bundledHelperSHA256: String(repeating: "ab", count: 32))
        #expect(script.contains(#"files=("$stage/openfortivpn")"#))
        #expect(script.contains(#"while IFS= read -r library; do files+=("$library"); done < <(find "$stage/lib" -type f | sort)"#))
        #expect(script.contains(#"printf '%s  %s\n' "${origin_hashes[$index]}" "${origins[$index]}""#))
        #expect(script.contains(#"binary_real="$(realpath "$source_binary")""#))
        #expect(script.contains("export LC_ALL=C"), "sort is bytewise")
    }

    @Test func testOpenSSLVersionString() throws {
        let tree = try Tree()
        #expect(OpenFortiVPNUpdateCheck.opensslVersion(in: tree.libraryReal("libcrypto.4.dylib")) == "OpenSSL 4.0.3 29 Sep 2026")
        #expect(OpenFortiVPNUpdateCheck.opensslVersion(in: tree.libraryReal("libssl.4.dylib")) == nil)
    }
}
