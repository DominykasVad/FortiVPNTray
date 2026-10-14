import Foundation
import os
import FortiVPNShared

/// `--verify-install`: the installer runs the freshly installed helper with only
/// this argument to check the openfortivpn copy as the helper will before every spawn.
enum InstallCheck {
    static let flag = HelperLaunchArguments.verifyInstallFlag

    /// 0 if the install passes `OpenFortiVPNInstall.verify()`, 1 otherwise, with the reason on stderr.
    static func run(install: OpenFortiVPNInstall = .production, output: FileHandle = .standardError) -> Int32 {
        do {
            try install.verify()
            return 0
        } catch {
            let reason = "The openfortivpn copy failed its check: \(error)\n"
            Logger(subsystem: AppIdentity.helperLabel, category: "install").error("\(reason, privacy: .public)")
            output.write(Data(reason.utf8))
            return 1
        }
    }
}
