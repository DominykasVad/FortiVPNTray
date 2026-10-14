import Foundation
import FortiVPNShared

/// What the helper must know to undo a session after a restart or sleep (PLAN.md 2.5).
/// Every field is validated when read back; the file is only ever written by the helper,
/// but a damaged one must never lead to a signal or a route change.
struct TunnelState: Codable, Equatable, Sendable {
    var sessionID: String
    var openfortivpn: ProcessIdentity?
    var pppd: ProcessIdentity?
    /// The session's ppp interface, `^ppp[0-9]+$`.
    var interface: String?
    /// The gateway's IPv4 address as the helper resolved it, for its host route.
    var serverIP: String?
    /// The IPv4 gateway of the default route before the session.
    var gateway: String?
    var dnsApplied: Bool

    init(sessionID: String, serverIP: String?, gateway: String?) {
        self.sessionID = sessionID
        self.serverIP = serverIP
        self.gateway = gateway
        dnsApplied = false
    }

    static func isPPPInterface(_ value: String) -> Bool {
        value.range(of: #"^ppp[0-9]{1,4}$"#, options: .regularExpression) != nil
    }

    var isValid: Bool {
        UUID(uuidString: sessionID) != nil
            && openfortivpn.map(\.isValid) != false
            && pppd.map(\.isValid) != false
            && interface.map(Self.isPPPInterface) != false
            && serverIP.map(Validation.ipv4) != false
            && gateway.map(Validation.ipv4) != false
    }

    private enum Keys: String, CodingKey, CaseIterable { case sessionID, openfortivpn, pppd, interface, serverIP, gateway, dnsApplied }
    private enum IdentityKeys: String, CodingKey, CaseIterable { case pid, startSeconds, startMicroseconds, executable }

    /// Strict: the top level and each identity may hold only known keys, and every value must be valid.
    static func decode(_ data: Data) throws -> TunnelState {
        guard data.count <= StateStore.maxSize else { throw StateStore.Failure(description: "The state file is too large.") }
        guard let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(object.keys).isSubset(of: Keys.allCases.map(\.rawValue)),
              ["openfortivpn", "pppd"].allSatisfy({ key in
                  object[key].map { ($0 as? [String: Any]).map { Set($0.keys) == Set(IdentityKeys.allCases.map(\.rawValue)) } ?? false } ?? true
              }),
              let state = try? JSONDecoder().decode(TunnelState.self, from: data), state.isValid else {
            throw StateStore.Failure(description: "The state file is not valid.")
        }
        return state
    }

    func encoded() -> Data {
        // A struct of strings, integers and booleans always encodes.
        try! JSONEncoder().encode(self)
    }
}

/// The state file in the helper's root-owned `0700` directory. Written atomically:
/// a new file `O_CREAT|O_EXCL|O_NOFOLLOW` `0600`, then `rename` over the old one.
struct StateStore: Sendable {
    struct Failure: Error, Equatable, CustomStringConvertible {
        let description: String
    }

    static let maxSize = 16 * 1024
    static let fileName = "state.json"
    static let temporaryName = "state.json.new"

    let directory: RunDirectory

    static let production = StateStore(directory: RunDirectory(path: AppIdentity.helperSupportDirectory, trust: .root, owner: 0))

    var path: String { directory.path + "/" + Self.fileName }

    /// The saved state, nil if there is none. Throws if the file is unreadable or invalid.
    func load() throws -> TunnelState? {
        try directory.prepare()
        let fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        if fd < 0 {
            if errno == ENOENT { return nil }
            throw Failure(description: "Cannot open the state file: \(String(cString: strerror(errno)))")
        }
        defer { close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFREG, info.st_uid == directory.owner,
              info.st_mode & 0o077 == 0 else {
            throw Failure(description: "The state file is not a regular 0600 file of uid \(directory.owner).")
        }
        guard info.st_size <= Self.maxSize else { throw Failure(description: "The state file is too large.") }
        var data = Data(count: Self.maxSize + 1)
        let count = data.withUnsafeMutableBytes { read(fd, $0.baseAddress, $0.count) }
        guard count >= 0 else { throw Failure(description: "Cannot read the state file: \(String(cString: strerror(errno)))") }
        return try TunnelState.decode(data.prefix(count))
    }

    func save(_ state: TunnelState) throws {
        try directory.prepare()
        directory.remove(Self.temporaryName)
        let temporary = try directory.create(Self.temporaryName, contents: state.encoded())
        guard rename(temporary, path) == 0 else {
            let reason = String(cString: strerror(errno))
            directory.remove(Self.temporaryName)
            throw Failure(description: "Cannot replace the state file: \(reason)")
        }
    }

    /// Removes the state file. Missing is not an error.
    func clear() {
        directory.remove(Self.fileName)
    }
}
