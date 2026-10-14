import Testing
import Foundation
import FortiVPNShared
@testable import FortiVPNHelper

/// `--verify-install`: the installer's check of the openfortivpn copy (PLAN.md 2.6).
struct InstallCheckTests {
    private func check(_ install: OpenFortiVPNInstall) -> (status: Int32, output: String) {
        let pipe = Pipe()
        let status = InstallCheck.run(install: install, output: pipe.fileHandleForWriting)
        try? pipe.fileHandleForWriting.close()
        return (status, String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self))
    }

    @Test func testAnIntactInstallPasses() throws {
        let fake = try FakeInstall()
        #expect(check(fake.install) == (0, ""))
    }

    @Test func testAFailedCheckSaysWhy() throws {
        let fake = try FakeInstall()
        try fake.write("tampered", to: fake.install.libraryDirectory + "/libssl.4.dylib", mode: 0o644)
        #expect(check(fake.install) == (1, "The openfortivpn copy failed its check: lib/libssl.4.dylib does not match the manifest\n"))

        let modules = try FakeInstall()
        try FakeInstall.makeDirectory(modules.install.modulesDirectory)
        #expect(check(modules.install).status == 1)
    }

    @Test func testTheFlagIsSharedAndNeverALaunchArgument() {
        #expect(InstallCheck.flag == "--verify-install")
        #expect(InstallCheck.flag == HelperLaunchArguments.verifyInstallFlag)
        // The plist can never carry it: the launch-argument parser rejects it.
        #expect(throws: HelperLaunchArguments.ParseError.self) {
            try HelperLaunchArguments(parsing: ["--allowed-uid", "501", "--uid-only", InstallCheck.flag])
        }
    }

    @Test func testProductionChecksTheInstalledCopy() {
        #expect(OpenFortiVPNInstall.production.directory == AppIdentity.openfortivpnDirectory)
        #expect(OpenFortiVPNInstall.production.trust.trustedOwners == [0])
    }
}
