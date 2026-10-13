import Testing
import Foundation
@testable import FortiVPNCore

struct CodeSignatureTests {
    private func run(_ executable: String, _ arguments: [String]) throws -> String {
        let process = Process(), pipe = Pipe()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        try process.run()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return String(decoding: data, as: UTF8.self)
    }

    @Test func testSHA1HexFormat() {
        #expect(CodeSignature.sha1Hex(Data()) == "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709")
        #expect(CodeSignature.sha1Hex(Data("abc".utf8)) == "A9993E364706816ABA3E25717850C26C9CD0D89D")
    }

    /// Same answer as the method `native/scripts/sign.sh` prints: extract the
    /// certificates with codesign and hash the first one.
    @Test func testLeafMatchesWhatCodesignExtracts() throws {
        let target = "/usr/bin/true"
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("leaf-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        _ = try run("/usr/bin/codesign", ["--display", "--extract-certificates=\(directory.path)/cert-", target])
        let expected = CodeSignature.sha1Hex(try Data(contentsOf: directory.appendingPathComponent("cert-0")))
        let leaf = try #require(CodeSignature.leafSHA1(ofCodeAt: URL(fileURLWithPath: target)))
        #expect(leaf == expected)
        #expect(leaf.count == 40)
        #expect(leaf == leaf.uppercased())
    }

    @Test func testAdHocAndUnsignedCodeHaveNoLeaf() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("leaf-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let adHoc = directory.appendingPathComponent("adhoc")
        try FileManager.default.copyItem(atPath: "/usr/bin/true", toPath: adHoc.path)
        _ = try run("/usr/bin/codesign", ["--force", "--sign", "-", adHoc.path])
        #expect(CodeSignature.leafSHA1(ofCodeAt: adHoc) == nil)
        let unsigned = directory.appendingPathComponent("plain.txt")
        try Data("not code".utf8).write(to: unsigned)
        #expect(CodeSignature.leafSHA1(ofCodeAt: unsigned) == nil)
        #expect(CodeSignature.leafSHA1(ofCodeAt: directory.appendingPathComponent("missing")) == nil)
    }

    @Test func testRunningTestProcessIsNotIdentitySigned() {
        // The test runner is ad-hoc signed by the linker; the installer would choose UID-only for it.
        #expect(CodeSignature.leafSHA1OfRunningCode() == nil)
    }
}
