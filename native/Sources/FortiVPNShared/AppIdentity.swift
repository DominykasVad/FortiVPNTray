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
    public static let dnsServiceKey = "State:/Network/Service/\(identifier)/DNS"
    public static let sessionLogPrefix = "/tmp/\(identifier)-"
}
