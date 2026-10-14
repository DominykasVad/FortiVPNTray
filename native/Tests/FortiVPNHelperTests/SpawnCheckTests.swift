import Testing
import Foundation
import FortiVPNShared
@testable import FortiVPNHelper

/// FileTrust, the install check and the run directory: what is verified before a spawn.
struct SpawnCheckTests {
    private func failure(_ body: () throws -> Void) -> String? {
        do { try body(); return nil } catch { return String(describing: error) }
    }

    // MARK: FileTrust

    @Test func testTrustAcceptsTheFakeTreeAndTheRealSystemDirectories() throws {
        let fake = try FakeInstall()
        try FakeInstall.trust.check(fake.install.binary, is: .file)
        try FakeInstall.trust.check(fake.install.directory, is: .directory)
        try FileTrust.root.check("/", is: .directory)
        try FileTrust.root.check("/usr/bin", is: .directory)
        try FileTrust.root.check("/bin/sh", is: .file)
    }

    @Test func testTrustRejectsNonCanonicalPaths() {
        for path in ["", "usr/bin", "/usr//bin", "/usr/bin/", "/usr/./bin", "/usr/../usr/bin", "/usr/bin/.."] {
            #expect(failure { try FileTrust.root.check(path, is: .directory) }?.contains("not a canonical absolute path") == true, "\(path)")
        }
    }

    @Test func testTrustRejectsWrongOwnerKindModeAndSymlinks() throws {
        let fake = try FakeInstall()
        let binary = fake.install.binary
        // Owned by the test user, which root-only trust does not accept.
        #expect(failure { try FileTrust.root.check(binary, is: .file) }?.contains("is owned by uid") == true)
        #expect(failure { try FakeInstall.trust.check(binary, is: .directory) }?.contains("is not a directory") == true)
        #expect(failure { try FakeInstall.trust.check(fake.install.directory, is: .file) }?.contains("is not a regular file") == true)
        #expect(failure { try FakeInstall.trust.check(fake.root + "/missing", is: .file) }?.contains("No such file") == true)

        chmod(binary, 0o775)
        #expect(failure { try FakeInstall.trust.check(binary, is: .file) }?.contains("group or other writable") == true)
        chmod(binary, 0o757)
        #expect(failure { try FakeInstall.trust.check(binary, is: .file) }?.contains("group or other writable") == true)
        chmod(binary, 0o755)
        // A writable directory anywhere above is as bad as a writable file.
        chmod(fake.install.directory, 0o777)
        #expect(failure { try FakeInstall.trust.check(binary, is: .file) }?.contains("\(fake.install.directory) is group or other writable") == true)
        chmod(fake.install.directory, 0o1777)
        #expect(failure { try FakeInstall.trust.check(binary, is: .file) } != nil, "sticky does not make it acceptable")
        chmod(fake.install.directory, 0o755)

        let link = fake.root + "/link"
        try FileManager.default.createSymbolicLink(atPath: link, withDestinationPath: binary)
        #expect(failure { try FakeInstall.trust.check(link, is: .file) }?.contains("is a symlink") == true)
        let linkedDirectory = fake.root + "/linked.d"
        try FileManager.default.createSymbolicLink(atPath: linkedDirectory, withDestinationPath: fake.install.directory)
        #expect(failure { try FakeInstall.trust.check(linkedDirectory + "/openfortivpn", is: .file) }?.contains("is a symlink") == true)
    }

    // MARK: Install

    @Test func testIntactInstallVerifies() throws {
        let fake = try FakeInstall()
        try fake.install.verify()
    }

    @Test func testProductionPaths() {
        let install = OpenFortiVPNInstall.production
        #expect(install.binary == "/Library/PrivilegedHelperTools/eu.dvad.fortivpntray.helper.d/openfortivpn")
        #expect(install.certsDirectory == "/Library/PrivilegedHelperTools/eu.dvad.fortivpntray.helper.d/certs")
        #expect(install.modulesDirectory == "/Library/PrivilegedHelperTools/eu.dvad.fortivpntray.helper.d/lib/ossl-modules")
        #expect(install.trust.trustedOwners == [0])
        #expect(RunDirectory.production.path == "/Library/Application Support/eu.dvad.fortivpntray.helper/run")
        #expect(RunDirectory.production.owner == 0)
        #expect(RunDirectory.production.trust.trustedOwners == [0])
    }

    @Test func testInstallRefusesChangedFiles() throws {
        let fake = try FakeInstall()
        try fake.write("#!/bin/sh\nexit 0\n", to: fake.install.binary, mode: 0o755)
        #expect(failure { try fake.install.verify() } == "openfortivpn does not match the manifest")

        let library = try FakeInstall()
        try library.write("other", to: library.install.libraryDirectory + "/libssl.4.dylib", mode: 0o644)
        #expect(failure { try library.install.verify() } == "lib/libssl.4.dylib does not match the manifest")
    }

    @Test func testInstallRefusesExtraOrMissingFiles() throws {
        let extra = try FakeInstall()
        try extra.write("evil", to: extra.install.libraryDirectory + "/libevil.dylib", mode: 0o644)
        #expect(failure { try extra.install.verify() } == "the files present do not match the manifest")

        let missing = try FakeInstall()
        try FileManager.default.removeItem(atPath: missing.install.libraryDirectory + "/libssl.4.dylib")
        #expect(failure { try missing.install.verify() } == "the files present do not match the manifest")

        // No provider modules: a directory under lib/ is not a manifest file.
        let modules = try FakeInstall()
        try FakeInstall.makeDirectory(modules.install.modulesDirectory)
        #expect(failure { try modules.install.verify() } == "the files present do not match the manifest")

        let unlisted = try FakeInstall()
        try unlisted.writeManifest { files, _ in files.removeLast() }
        #expect(failure { try unlisted.install.verify() } == "the files present do not match the manifest")

        let escaping = try FakeInstall()
        try escaping.writeManifest { files, _ in files[1]["file"] = "lib/../../../bin/sh" }
        #expect(failure { try escaping.install.verify() } == "the files present do not match the manifest")
    }

    @Test func testInstallRefusesABadManifest() throws {
        let duplicate = try FakeInstall()
        try duplicate.writeManifest { files, _ in files.append(files[0]) }
        #expect(failure { try duplicate.install.verify() } == "the manifest lists openfortivpn twice")

        let wrongSet = try FakeInstall()
        try wrongSet.writeManifest { _, set in set = String(repeating: "0", count: 64) }
        #expect(failure { try wrongSet.install.verify() } == "the file set does not match the manifest")

        let garbage = try FakeInstall()
        try FileManager.default.removeItem(atPath: garbage.install.manifest)
        try garbage.write("{\"files\": 3}", to: garbage.install.manifest, mode: 0o644)
        #expect(failure { try garbage.install.verify() }?.contains("is not a valid manifest") == true)

        let writable = try FakeInstall()
        chmod(writable.install.manifest, 0o666)
        #expect(failure { try writable.install.verify() }?.contains("manifest.json is group or other writable") == true)
    }

    @Test func testInstallRefusesAnUnsafeCertsDirectory() throws {
        let filled = try FakeInstall()
        try filled.write("-----BEGIN CERTIFICATE-----\n", to: filled.install.certsDirectory + "/60b97ac1.0", mode: 0o644)
        #expect(failure { try filled.install.verify() }?.hasSuffix("/certs is not empty") == true)

        let missing = try FakeInstall()
        try FileManager.default.removeItem(atPath: missing.install.certsDirectory)
        #expect(failure { try missing.install.verify() }?.contains("certs: No such file") == true)

        let writable = try FakeInstall()
        chmod(writable.install.certsDirectory, 0o777)
        #expect(failure { try writable.install.verify() }?.contains("certs is group or other writable") == true)
    }

    @Test func testInstallRefusesAWritableOrLinkedBinaryOrLibrary() throws {
        let binary = try FakeInstall()
        chmod(binary.install.binary, 0o777)
        #expect(failure { try binary.install.verify() }?.contains("is group or other writable") == true)

        let linked = try FakeInstall()
        let library = linked.install.libraryDirectory + "/libssl.4.dylib"
        try linked.write("ssl", to: linked.root + "/elsewhere.dylib", mode: 0o644)
        try FileManager.default.removeItem(atPath: library)
        try FileManager.default.createSymbolicLink(atPath: library, withDestinationPath: linked.root + "/elsewhere.dylib")
        #expect(failure { try linked.install.verify() }?.contains("libssl.4.dylib is a symlink") == true)
    }

    // MARK: Run directory

    @Test func testRunDirectoryIsCreated0700AndFiles0600() throws {
        let fake = try FakeInstall()
        let run = fake.runDirectory
        try run.prepare()
        try run.prepare()   // Already there: fine.
        for directory in [run.path, (run.path as NSString).deletingLastPathComponent] {
            var info = stat()
            #expect(lstat(directory, &info) == 0 && info.st_mode & 0o7777 == 0o700, "\(directory)")
        }
        let path = try run.create("a.conf", contents: Data("host = vpn.example.com\n".utf8))
        #expect(path == run.path + "/a.conf")
        var info = stat()
        #expect(lstat(path, &info) == 0 && info.st_mode & 0o7777 == 0o600 && info.st_mode & S_IFMT == S_IFREG)
        #expect(try String(contentsOfFile: path, encoding: .utf8) == "host = vpn.example.com\n")
        run.remove("a.conf")
        #expect(fake.configFiles().isEmpty)
        run.remove("a.conf")   // Missing: fine.
    }

    @Test func testRunDirectoryRefusesWrongModeOrOwner() throws {
        let fake = try FakeInstall()
        try fake.runDirectory.prepare()
        chmod(fake.runDirectory.path, 0o755)
        #expect(failure { try fake.runDirectory.prepare() }?.contains("with mode 0700") == true)
        chmod(fake.runDirectory.path, 0o700)
        let otherOwner = RunDirectory(path: fake.runDirectory.path, trust: FakeInstall.trust, owner: getuid() + 1)
        #expect(failure { try otherOwner.prepare() }?.contains("is not owned by uid") == true)
    }

    @Test func testRunDirectoryNeverFollowsOrReusesAnExistingName() throws {
        let fake = try FakeInstall()
        let run = fake.runDirectory
        try run.prepare()
        _ = try run.create("a.conf", contents: Data("first".utf8))
        #expect(failure { _ = try run.create("a.conf", contents: Data("second".utf8)) }?.contains("File exists") == true)
        #expect(try String(contentsOfFile: run.path + "/a.conf", encoding: .utf8) == "first")

        let target = fake.root + "/target"
        try FileManager.default.createSymbolicLink(atPath: run.path + "/b.conf", withDestinationPath: target)
        #expect(failure { _ = try run.create("b.conf", contents: Data("x".utf8)) } != nil)
        #expect(!FileManager.default.fileExists(atPath: target))

        for name in ["", "../x.conf", "a/b.conf", ".hidden"] {
            #expect(failure { _ = try run.create(name, contents: Data()) } == "Bad file name", "\(name)")
        }
    }
}
