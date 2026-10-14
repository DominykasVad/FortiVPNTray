import Foundation
import Darwin
import FortiVPNShared

public struct PollResult: Sendable {
    public var lines: [String] = []
    public var events: [LogEvent] = []
    public var exitMessage: String?
    public var received: UInt64 = 0
    public var sent: UInt64 = 0
}

/// The SAML login URL the app is willing to open (PLAN.md 3.1). The helper builds
/// it from the validated request, but the app checks it again before handing it to
/// the browser: https, the profile's host and port, and the login path only.
public enum SAMLLogin {
    public static let path = "/remote/saml/start"

    public static func isExpected(_ url: URL, host: String, port: Int) -> Bool {
        guard let parts = URLComponents(url: url, resolvingAgainstBaseURL: false) else { return false }
        return parts.scheme == "https" && parts.host?.lowercased() == host.lowercased() && parts.port == port
            && parts.path == path && parts.user == nil && parts.password == nil && parts.fragment == nil
    }
}

/// The app's side of a VPN session: a client of the helper (PLAN.md phase 3). The
/// helper starts openfortivpn, applies and undoes routes and DNS, and keeps the
/// redacted log; this actor turns its status and log into what the UI shows.
public actor VPNEngine {
    private struct Session {
        let id: String
        let host: String
        let port: Int
        var offset = 0
        var parser = LogParser()
        var connected = false
        var seenSAMLURLs: Set<URL> = []
    }

    private let helper: any HelperAPI
    private var session: Session?

    public var hasSession: Bool { session != nil }

    public init(helper: any HelperAPI = HelperXPCClient()) { self.helper = helper }

    public func start(profile: VPNProfile, settings: AppSettings) async throws {
        guard session == nil else { throw VPNError("Disconnect the current session before reconnecting.") }
        let version = try helper.version()
        guard version.protocolVersion == HelperTransport.protocolVersion else {
            throw VPNError("The helper speaks protocol \(version.protocolVersion); this app requires protocol \(HelperTransport.protocolVersion). Repair the helper in Settings.")
        }
        let profile = try profile.validated()
        try Task.checkCancellation()
        let request: ConnectRequest
        do {
            request = try ConnectRequest(host: profile.host, port: profile.port, realm: profile.realm, trustedCerts: profile.trustedCerts,
                                         useSystemDNSFallback: settings.dnsFallback)
        } catch {
            throw VPNError(error.description)
        }
        let id = try helper.connect(request)
        session = Session(id: id, host: profile.host, port: profile.port)
    }

    public func poll() throws -> PollResult {
        guard var current = session else { return PollResult() }
        var result = PollResult()
        // The log first, so a session's last lines are shown before its end.
        read(into: &result, session: &current, chunk: try helper.readLog(sessionID: current.id, offset: current.offset))
        let status = try helper.status()
        guard status.sessionID == current.id else {
            // The session is over: the child exited, or someone else disconnected it.
            // Its log is kept by the helper; collect what is left.
            for _ in 0..<20 {
                guard let chunk = try? helper.readLog(sessionID: current.id, offset: current.offset), !chunk.lines.isEmpty else { break }
                read(into: &result, session: &current, chunk: chunk)
            }
            result.exitMessage = status.lastError ?? (current.connected ? "The VPN connection ended." : "openfortivpn exited before the tunnel was established.")
            session = nil
            return result
        }
        if status.state == .connected && !current.connected {
            current.connected = true
            result.events.append(.connected(status.vpnIP ?? "unknown"))
        }
        if !current.connected, let url = try helper.pendingSAMLURL(), current.seenSAMLURLs.insert(url).inserted {
            if SAMLLogin.isExpected(url, host: current.host, port: current.port) {
                result.events.append(.saml(url))
            } else {
                result.lines.append("ERROR:  The helper offered an unexpected login URL; it was not opened.")
            }
        }
        if current.connected, let interface = status.interface {
            (result.received, result.sent) = Self.interfaceBytes(interface)
        }
        session = current
        return result
    }

    public func stop() throws {
        guard session != nil else { return }
        try helper.disconnect()
        session = nil
    }

    /// Lines are already redacted by the helper. The parser only looks for the
    /// gateway certificate digest; connection state comes from the helper's status.
    private func read(into result: inout PollResult, session: inout Session, chunk: LogChunk) {
        session.offset = max(session.offset, chunk.nextOffset)
        for line in chunk.lines {
            result.lines.append(line)
            for event in session.parser.consume(line) {
                if case .certificate = event { result.events.append(event) }
            }
        }
    }

    /// Bytes in and out of the tunnel interface (`ppp0` etc.), read unprivileged.
    static func interfaceBytes(_ interface: String) -> (UInt64, UInt64) {
        guard interface.range(of: #"^ppp[0-9]+$"#, options: .regularExpression) != nil else { return (0, 0) }
        var start: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&start) == 0, let first = start else { return (0, 0) }
        defer { freeifaddrs(first) }
        var cursor: UnsafeMutablePointer<ifaddrs>? = first
        while let pointer = cursor {
            let info = pointer.pointee
            if String(cString: info.ifa_name) == interface, let address = info.ifa_addr,
               Int32(address.pointee.sa_family) == AF_LINK, let data = info.ifa_data {
                let stats = data.assumingMemoryBound(to: if_data.self).pointee
                return (UInt64(stats.ifi_ibytes), UInt64(stats.ifi_obytes))
            }
            cursor = info.ifa_next
        }
        return (0, 0)
    }
}
