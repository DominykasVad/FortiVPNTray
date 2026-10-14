import CryptoKit
import Foundation
import Darwin
import FortiVPNShared

public struct HelperResponse: Decodable {
    public let ok: Bool
    public let error: String?
    public let pid: Int32?
    public let version: String?
}

public struct HelperClient {
    public let socketPath: String
    private let timeoutSeconds: Int
    public init(socketPath: String = AppIdentity.socketPath, timeoutSeconds: Int = 30) {
        self.socketPath = socketPath; self.timeoutSeconds = max(1, timeoutSeconds)
    }

    public func request(_ fields: [String: Any]) throws -> HelperResponse {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw VPNError("Could not create helper connection.") }
        defer { close(fd) }
        var timeout = timeval(tv_sec: timeoutSeconds, tv_usec: 0)
        var noSignal: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &noSignal, socklen_t(MemoryLayout<Int32>.size))
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let path = Array(socketPath.utf8CString)
        guard path.count <= MemoryLayout.size(ofValue: address.sun_path) else { throw VPNError("Helper socket path is too long.") }
        withUnsafeMutableBytes(of: &address.sun_path) { buffer in
            path.withUnsafeBytes { buffer.copyBytes(from: $0) }
        }
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        let result = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard result == 0 else { throw VPNError("Helper unavailable. Install or repair it in Settings before connecting.") }
        var payload = try JSONSerialization.data(withJSONObject: fields)
        payload.append(10)
        try payload.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let n = Darwin.write(fd, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                if n < 0 && errno == EINTR { continue }
                guard n > 0 else { throw VPNError("Could not send the helper request.") }
                offset += n
            }
        }
        shutdown(fd, SHUT_WR)
        var reply = Data()
        var buffer = [UInt8](repeating: 0, count: 4096)
        while !reply.contains(10) {
            let count = Darwin.read(fd, &buffer, buffer.count)
            if count < 0 && errno == EINTR { continue }
            guard count > 0 else {
                throw VPNError("Helper response was interrupted or timed out. Check the VPN process before retrying.")
            }
            reply.append(contentsOf: buffer.prefix(count))
            guard reply.count <= 65536 else { throw VPNError("Helper response exceeds the allowed size.") }
        }
        let response = try JSONDecoder().decode(HelperResponse.self, from: reply)
        guard response.ok else { throw VPNError(response.error ?? "Helper request failed.") }
        return response
    }
    public func version() throws -> String { try request(["cmd": "ping"]).version ?? "unknown" }
}

public enum Commands {
    public struct Output {
        public let status: Int32
        public let text: String
    }
    public static func run(_ executable: String, _ args: [String], input: Data? = nil) throws -> Output {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = args
        let output = Pipe()
        process.standardOutput = output
        process.standardError = output
        if let input {
            let pipe = Pipe()
            process.standardInput = pipe
            try process.run()
            try pipe.fileHandleForWriting.write(contentsOf: input)
            try pipe.fileHandleForWriting.close()
        } else {
            process.standardInput = FileHandle.nullDevice
            try process.run()
        }
        let data = output.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return Output(status: process.terminationStatus, text: String(decoding: data, as: UTF8.self))
    }
    public static func shellQuote(_ value: String) -> String { "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'" }
    /// Runs `script` with bash as root behind one admin prompt. The script travels as an
    /// argument to the AppleScript, never inside its source, so nothing in it needs
    /// AppleScript escaping; the shell sees it as one single-quoted word.
    public static func administrator(script: String) throws {
        let result = try run("/usr/bin/osascript", ["-e", "on run argv", "-e", "do shell script (item 1 of argv) with administrator privileges", "-e", "end run",
                                                    administratorCommand(script: script)])
        guard result.status == 0 else { throw VPNError(administratorError(result.text)) }
    }
    static func administratorCommand(script: String) -> String {
        "/bin/bash -c " + shellQuote(script)
    }
    /// osascript reports a failed script as "<file>: execution error: <stderr> (<code>)".
    static func administratorError(_ text: String) -> String {
        var message = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if let range = message.range(of: "execution error: ") { message = String(message[range.upperBound...]) }
        if let range = message.range(of: #" \(-?[0-9]+\)$"#, options: .regularExpression) { message.removeSubrange(range) }
        return message.contains("User canceled") ? "The administrator prompt was cancelled." : message
    }
}

public enum HelperInstaller {
    /// Installs or repairs the helper behind one admin prompt (PLAN.md 2.6). The allowed
    /// UID is this app's user and the pinned certificate is the one this app is signed
    /// with; both are read here, never typed. Returns the caller check the helper now
    /// uses: `.uidOnly` means the app is ad-hoc signed, which the UI must say.
    public static func install(resourceDirectory: URL) throws -> CallerCheckMode {
        let source = resourceDirectory.appendingPathComponent(HelperInstallScript.bundledHelperName)
        guard FileManager.default.isExecutableFile(atPath: source.path) else { throw VPNError("The bundled helper is missing. Rebuild the .app using native/scripts/build.sh.") }
        let uid = getuid()
        guard uid != 0 else { throw VPNError("Run FortiVPNTray as your own user, not as root.") }
        let leaf = CodeSignature.leafSHA1OfRunningCode()
        let arguments = try HelperLaunchArguments(allowedUID: uid, callerCheck: leaf.map { .signed(leafSHA1: $0) } ?? .uidOnly)
        let hash = SHA256.hash(data: try Data(contentsOf: source)).map { String(format: "%02x", $0) }.joined()
        try Commands.administrator(script: try HelperInstallScript.install(arguments: arguments, bundledHelper: source.path, bundledHelperSHA256: hash))
        return arguments.callerCheck.mode
    }

    /// Refused while the helper reports a session; the script refuses too while the
    /// helper's state file exists, in case the helper cannot be asked.
    public static func uninstall() throws {
        if let status = try? HelperXPCClient().status(), status.state != .idle {
            throw VPNError("A VPN session is active. Disconnect before uninstalling the helper.")
        }
        try Commands.administrator(script: HelperInstallScript.uninstall())
    }
}

/// A failed version call alone does not mean the helper is not installed.
public struct HelperInstallationStatus: Equatable, Sendable {
    public enum State { case missing, incomplete, unavailable, ready, versionMismatch }
    public let executablePresent: Bool
    public let launchDaemonPresent: Bool
    /// What the running helper reported, nil if it did not answer.
    public let helper: HelperVersion?
    public init(executablePresent: Bool, launchDaemonPresent: Bool, helper: HelperVersion?) {
        self.executablePresent = executablePresent
        self.launchDaemonPresent = launchDaemonPresent
        self.helper = helper
    }
    public var state: State {
        if let helper {
            guard executablePresent && launchDaemonPresent else { return .incomplete }
            return helper.protocolVersion == HelperTransport.protocolVersion ? .ready : .versionMismatch
        }
        if executablePresent && launchDaemonPresent { return .unavailable }
        return executablePresent || launchDaemonPresent ? .incomplete : .missing
    }
    public var title: String {
        switch state {
        case .missing: return "Not installed"
        case .incomplete: return "Installation needs repair"
        case .unavailable: return "Installed · not responding"
        case .ready: return "Installed and running"
        case .versionMismatch: return "Installed · update required"
        }
    }
    public var detail: String {
        switch state {
        case .missing: return "Install the helper to connect to a VPN."
        case .incomplete: return "Helper files are incomplete. Repair the installation."
        case .unavailable: return "The helper is installed, but could not be reached. Try Refresh or Repair."
        case .ready:
            let version = "Version \(helper?.version ?? "") · \(helper?.mode.title ?? "")"
            return helper?.mode == .uidOnly ? "\(version) · \(Self.uidOnlyWarning)" : "\(version) · Ready to connect."
        case .versionMismatch: return "The helper speaks protocol \(helper?.protocolVersion ?? 0); this app requires protocol \(HelperTransport.protocolVersion). Repair the installation."
        }
    }
    /// Shown whenever the helper runs without the signed caller check.
    public static let uidOnlyWarning = "This app is ad-hoc signed, so the helper accepts any process running as you. Build with the local signing identity (docs/signing.md) and repair the helper."
    public static func inspect() -> Self {
        let files = FileManager.default
        return Self(executablePresent: files.fileExists(atPath: AppIdentity.helperExecutablePath),
                    launchDaemonPresent: files.fileExists(atPath: AppIdentity.launchDaemonPlistPath),
                    helper: try? HelperXPCClient().version())
    }
}
