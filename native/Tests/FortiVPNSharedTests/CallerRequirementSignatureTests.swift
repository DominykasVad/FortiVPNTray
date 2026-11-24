import Testing
import Foundation
import FortiVPNShared

/// The build clause of the caller requirement, checked by the system against real code
/// signatures. The bundles are ad-hoc signed, which seals the Info.plist exactly as the
/// local identity does; the certificate part of the requirement needs that identity and
/// is checked by hand (spikes/helper-probe).
struct CallerRequirementSignatureTests {
    private static let identifier = "com.example.fake"

    private func withDirectory(_ body: (URL) throws -> Void) throws {
        let files = FileManager.default
        let root = files.temporaryDirectory.appendingPathComponent("requirement-test-\(UUID().uuidString)")
        try files.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? files.removeItem(at: root) }
        try body(root)
    }

    /// An ad-hoc signed app whose Info.plist says `build`, or has no `CFBundleVersion` at all.
    private func bundle(in root: URL, build: String?) throws -> URL {
        let app = root.appendingPathComponent("\(UUID().uuidString)/Fake.app")
        let contents = app.appendingPathComponent("Contents")
        try FileManager.default.createDirectory(at: contents.appendingPathComponent("MacOS"), withIntermediateDirectories: true)
        try FileManager.default.copyItem(atPath: "/usr/bin/true", toPath: contents.appendingPathComponent("MacOS/Fake").path)
        try write(build: build, to: app)
        try sign(app)
        return app
    }

    private func write(build: String?, to app: URL) throws {
        var plist: [String: Any] = ["CFBundleIdentifier": Self.identifier, "CFBundleExecutable": "Fake", "CFBundlePackageType": "APPL"]
        plist["CFBundleVersion"] = build
        try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0)
            .write(to: app.appendingPathComponent("Contents/Info.plist"))
    }

    private func codesign(_ arguments: [String]) throws -> Int32 {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/codesign")
        process.arguments = arguments
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try process.run()
        process.waitUntilExit()
        return process.terminationStatus
    }

    private func sign(_ url: URL) throws {
        try #require(try codesign(["--force", "--sign", "-", "--identifier", Self.identifier, url.path]) == 0)
    }

    /// Whether the code at `url` is validly signed and satisfies `requirement`, as `codesign` judges it.
    private func satisfies(_ url: URL, _ requirement: String) throws -> Bool {
        try codesign(["--verify", "-R=" + requirement, url.path]) == 0
    }

    /// The last part of the helper's requirement: `info[CFBundleVersion] >= "<minimum>"`.
    private func buildClause(_ minimum: Int) throws -> String {
        let whole = try #require(CallerRequirement.string(identifier: AppIdentity.identifier, leafSHA1: String(repeating: "A", count: 40), minimumBuild: minimum))
        return try #require(whole.components(separatedBy: " and ").last)
    }

    private var identifierOnly: String { "identifier \"\(Self.identifier)\"" }
    private func withMinimumBuild6() throws -> String { identifierOnly + " and " + (try buildClause(6)) }

    @Test func testTheWholeRequirementCompiles() throws {
        let requirement = try #require(CallerRequirement.string(identifier: AppIdentity.identifier, leafSHA1: String(repeating: "A", count: 40)))
        #expect(try buildClause(6) == "info[CFBundleVersion] >= \"6\"")
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/csreq")
        process.arguments = ["-r=" + requirement, "-t"]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try process.run()
        process.waitUntilExit()
        #expect(process.terminationStatus == 0)
    }

    @Test func testEarlierBuildsAreRefusedAndLaterOnesAccepted() throws {
        try withDirectory { root in
            for (build, accepted) in [("5", false), ("1", false), ("6", true), ("7", true), ("10", true), ("60", true)] {
                let app = try bundle(in: root, build: build)
                // The identifier alone is satisfied, so a refusal is the build clause's.
                #expect(try satisfies(app, identifierOnly), "build \(build)")
                #expect(try satisfies(app, try withMinimumBuild6()) == accepted, "build \(build)")
            }
        }
    }

    @Test func testCodeWithoutABuildNumberIsRefused() throws {
        try withDirectory { root in
            let noVersion = try bundle(in: root, build: nil)
            #expect(try satisfies(noVersion, identifierOnly))
            #expect(try !satisfies(noVersion, try withMinimumBuild6()))

            // A plain executable such as the signed test probe: no Info.plist at all.
            let tool = root.appendingPathComponent("tool")
            try FileManager.default.copyItem(atPath: "/usr/bin/true", toPath: tool.path)
            try sign(tool)
            #expect(try satisfies(tool, identifierOnly))
            #expect(try !satisfies(tool, try withMinimumBuild6()))
        }
    }

    @Test func testAnOldBuildCannotClaimANewerNumber() throws {
        try withDirectory { root in
            let app = try bundle(in: root, build: "5")
            // Edited after signing, as someone holding an old signed build could do.
            try write(build: "6", to: app)
            #expect(try !satisfies(app, try withMinimumBuild6()))
            #expect(try !satisfies(app, identifierOnly))   // the signature no longer matches at all
        }
    }
}
