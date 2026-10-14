import Testing
import Foundation

/// `native/scripts/sign.sh` on a throwaway bundle. The signed path needs the
/// maintainer's local identity and is checked by hand (docs/signing.md).
struct SigningScriptTests {
    private static let script = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        .appendingPathComponent("scripts/sign.sh")

    private struct Result { let status: Int32; let output: String }

    private func withBundle(_ body: (URL) throws -> Void) throws {
        let files = FileManager.default
        let root = files.temporaryDirectory.appendingPathComponent("sign-test-\(UUID().uuidString)")
        defer { try? files.removeItem(at: root) }
        let contents = root.appendingPathComponent("Fake.app/Contents")
        try files.createDirectory(at: contents.appendingPathComponent("MacOS"), withIntermediateDirectories: true)
        try files.createDirectory(at: contents.appendingPathComponent("Resources"), withIntermediateDirectories: true)
        try files.copyItem(atPath: "/usr/bin/true", toPath: contents.appendingPathComponent("MacOS/Fake").path)
        try files.copyItem(atPath: "/usr/bin/true", toPath: contents.appendingPathComponent("Resources/FortiVPNHelper").path)
        let plist: [String: Any] = ["CFBundleIdentifier": "com.example.fake", "CFBundleExecutable": "Fake", "CFBundlePackageType": "APPL"]
        try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0).write(to: contents.appendingPathComponent("Info.plist"))
        try body(root.appendingPathComponent("Fake.app"))
    }

    private func run(_ executable: String, _ arguments: [String], environment: [String: String] = [:]) throws -> Result {
        let process = Process(), pipe = Pipe()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        process.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin"].merging(environment) { $1 }
        process.standardOutput = pipe
        process.standardError = pipe
        process.standardInput = FileHandle.nullDevice
        try process.run()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return Result(status: process.terminationStatus, output: String(decoding: data, as: UTF8.self))
    }
    private func sign(_ app: URL, _ environment: [String: String]) throws -> Result {
        try run(Self.script.path, [app.path], environment: environment)
    }
    private func signature(_ path: String) throws -> String { try run("/usr/bin/codesign", ["-dv", path]).output }

    @Test func testUnsetIdentitySignsAdHocWithLoudWarning() throws {
        try withBundle { app in
            for environment in [[:], ["FVT_SIGN_IDENTITY": "-"], ["FVT_SIGN_IDENTITY": ""]] {
                let result = try sign(app, environment)
                #expect(result.status == 0, "\(result.output)")
                #expect(result.output.contains("WARNING"))
                #expect(result.output.contains("AD-HOC"))
                #expect(result.output.contains("UID-ONLY"))
                #expect(!result.output.contains("Leaf certificate SHA-1"))
                #expect(try signature(app.path).contains("Signature=adhoc"))
                #expect(try signature(app.appendingPathComponent("Contents/Resources/FortiVPNHelper").path).contains("Signature=adhoc"))
                #expect(try run("/usr/bin/codesign", ["--verify", "--deep", "--strict", app.path]).status == 0)
            }
        }
    }

    @Test func testUnknownIdentityFailsInsteadOfFallingBackToAdHoc() throws {
        try withBundle { app in
            let result = try sign(app, ["FVT_SIGN_IDENTITY": "FortiVPNTray Test No Such Identity \(UUID().uuidString)"])
            #expect(result.status != 0)
            #expect(!result.output.contains("AD-HOC"))
            #expect(!result.output.contains("Leaf certificate SHA-1"))
            // Nothing was signed: the copied system binary keeps its own signature.
            #expect(try !signature(app.path).contains("Signature=adhoc"))
        }
    }

    @Test func testKeychainWithoutIdentityIsRejected() throws {
        try withBundle { app in
            let result = try sign(app, ["FVT_SIGN_KEYCHAIN": "/nonexistent.keychain-db"])
            #expect(result.status != 0)
            #expect(result.output.contains("FVT_SIGN_KEYCHAIN is set but FVT_SIGN_IDENTITY is not"))
        }
    }

    @Test func testMissingArgumentFails() throws {
        #expect(try run(Self.script.path, []).status != 0)
    }
}
