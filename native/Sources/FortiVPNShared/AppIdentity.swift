import Foundation

/// Every name the fork puts on the system. The Rust helper keeps its own
/// copies until it is replaced; `IdentityTests` fails if they drift.
public enum AppIdentity {
    public static let identifier = "eu.dvad.fortivpntray"
    public static let helperLabel = "\(identifier).helper"
    public static let helperVersion = "0.1.9"
    public static let socketPath = "/var/run/\(helperLabel).sock"
    public static let helperLogPath = "/var/log/\(helperLabel).log"
    public static let helperExecutablePath = "/Library/PrivilegedHelperTools/\(helperLabel)"
    public static let launchDaemonPlistPath = "/Library/LaunchDaemons/\(helperLabel).plist"
    /// Root-owned copy of openfortivpn and its dylibs (S2), made by the installer.
    public static let openfortivpnDirectory = "/Library/PrivilegedHelperTools/\(helperLabel).d"
    /// Root-owned `0700` directory for the helper's state file.
    public static let helperSupportDirectory = "/Library/Application Support/\(helperLabel)"
    /// The helper's state file (PLAN.md 2.5); it exists while a session needs cleaning up.
    public static let helperStateFile = "\(helperSupportDirectory)/state.json"
    /// Root-owned `0700` directory for per-session openfortivpn config files.
    public static let helperRunDirectory = "\(helperSupportDirectory)/run"
    public static let dnsServiceKey = "State:/Network/Service/\(identifier)/DNS"
    public static let sessionLogPrefix = "/tmp/\(identifier)-"
}
