import CryptoKit
import Foundation
import FortiVPNShared

/// Which openfortivpn and OpenSSL a set of files is.
public struct OpenFortiVPNVersions: Equatable, Sendable {
    public let openfortivpn: String
    public let openssl: String

    public init(openfortivpn: String, openssl: String) {
        self.openfortivpn = openfortivpn
        self.openssl = openssl
    }

    public var summary: String { "openfortivpn \(openfortivpn.isEmpty ? "?" : openfortivpn) · \(openssl.isEmpty ? "OpenSSL ?" : openssl)" }
}

/// Whether Homebrew's openfortivpn differs from the helper's copy (PLAN.md 3.4).
public struct OpenFortiVPNUpdateStatus: Equatable, Sendable {
    public enum State: Equatable, Sendable {
        /// No copy installed: the helper is not installed (or not by this version).
        case notInstalled
        case upToDate
        /// Homebrew's binary or a library it loads changed since the copy was made.
        case updateAvailable
        /// The copy keeps working; there is nothing to update from.
        case homebrewMissing
        /// The comparison could not be made; the reason is shown.
        case unknown(String)
    }

    public let state: State
    public let installed: OpenFortiVPNVersions?
    public let homebrew: OpenFortiVPNVersions?

    public init(state: State, installed: OpenFortiVPNVersions? = nil, homebrew: OpenFortiVPNVersions? = nil) {
        self.state = state
        self.installed = installed
        self.homebrew = homebrew
    }

    public var detail: String {
        switch state {
        case .notInstalled: return "Installed with the helper."
        case .upToDate: return "\(installed?.summary ?? "") · Same as Homebrew."
        case .updateAvailable:
            return "Installed: \(installed?.summary ?? "?")\nHomebrew: \(homebrew?.summary ?? "?")"
        case .homebrewMissing: return "\(installed?.summary ?? "") · Homebrew's openfortivpn is missing; the installed copy keeps working."
        case .unknown(let reason): return "\(installed?.summary ?? "") · Could not compare with Homebrew: \(reason)"
        }
    }
}

/// Compares the helper's openfortivpn copy with Homebrew's current files, as the user
/// and read-only. The installed side comes from the copy's `manifest.json` (root-owned,
/// world-readable); it decides only what Settings shows and whether Update is offered,
/// never anything the helper relies on: the helper checks the copy itself before each
/// spawn, and Update is the ordinary admin-prompt install.
///
/// The comparison is the hash of the whole set, so an OpenSSL update is noticed even
/// when openfortivpn's version stays the same. It mirrors the installer
/// (`HelperInstallScript`): the binary's real path, every non-system library found by
/// walking `otool -L`, each by real path; the binary first, then the libraries sorted by
/// file name; one `<sha256>  <real path>` line each, hashed.
public enum OpenFortiVPNUpdateCheck {
    public static let manifestPath = AppIdentity.openfortivpnDirectory + "/manifest.json"
    static let maxManifestSize = 1 << 20

    struct Manifest: Decodable {
        let openfortivpn_version: String?
        let openssl_version: String?
        let source_set_sha256: String
    }

    public static func check(manifest: String = manifestPath, homebrewBinary: String = HelperInstallScript.homebrewOpenFortiVPN,
                             libraries: (String) throws -> [String] = loadedLibraries) -> OpenFortiVPNUpdateStatus {
        guard FileManager.default.fileExists(atPath: manifest) else { return OpenFortiVPNUpdateStatus(state: .notInstalled) }
        guard let data = FileManager.default.contents(atPath: manifest), data.count <= maxManifestSize,
              let parsed = try? JSONDecoder().decode(Manifest.self, from: data), isSHA256(parsed.source_set_sha256) else {
            return OpenFortiVPNUpdateStatus(state: .unknown("the installed copy's manifest cannot be read. Repair the helper."))
        }
        let installed = OpenFortiVPNVersions(openfortivpn: parsed.openfortivpn_version ?? "", openssl: parsed.openssl_version ?? "")
        guard FileManager.default.fileExists(atPath: homebrewBinary) else {
            return OpenFortiVPNUpdateStatus(state: .homebrewMissing, installed: installed)
        }
        do {
            let current = try homebrewSet(binary: homebrewBinary, libraries: libraries)
            let state: OpenFortiVPNUpdateStatus.State = current.setSHA256 == parsed.source_set_sha256 ? .upToDate : .updateAvailable
            return OpenFortiVPNUpdateStatus(state: state, installed: installed, homebrew: current.versions)
        } catch {
            return OpenFortiVPNUpdateStatus(state: .unknown(String(describing: error)), installed: installed)
        }
    }

    struct HomebrewSet: Equatable {
        let setSHA256: String
        let versions: OpenFortiVPNVersions
    }

    struct Failure: Error, CustomStringConvertible {
        let description: String
    }

    static func homebrewSet(binary: String, libraries: (String) throws -> [String]) throws -> HomebrewSet {
        let binaryReal = try realPath(binary)
        var byName: [String: String] = [:]      // library file name → real path
        var queue = [binaryReal]
        var next = 0
        while next < queue.count {
            let current = queue[next]
            next += 1
            for reference in try libraries(current) where !reference.hasPrefix("/usr/lib/") && !reference.hasPrefix("/System/") {
                guard reference.hasPrefix("/") else { throw Failure(description: "\(current) loads \(reference), which the installer does not handle.") }
                let real = try realPath(reference)
                let name = (real as NSString).lastPathComponent
                if let known = byName[name] {
                    guard known == real else { throw Failure(description: "two different libraries are both called \(name).") }
                } else if real != binaryReal {
                    byName[name] = real
                    queue.append(real)
                }
            }
        }
        let ordered = [binaryReal] + byName.keys.sorted { $0.utf8.lexicographicallyPrecedes($1.utf8) }.map { byName[$0]! }
        var lines = ""
        for path in ordered { lines += "\(try sha256(of: path))  \(path)\n" }
        let keg = ((binaryReal as NSString).deletingLastPathComponent as NSString).deletingLastPathComponent
        let kegName = (keg as NSString).lastPathComponent
        let version = kegName.range(of: #"_[0-9]+$"#, options: .regularExpression).map { String(kegName[..<$0.lowerBound]) } ?? kegName
        let crypto = byName.first { $0.key.hasPrefix("libcrypto.") }?.value
        let versions = OpenFortiVPNVersions(openfortivpn: version, openssl: crypto.flatMap(opensslVersion(in:)) ?? "")
        return HomebrewSet(setSHA256: sha256(Data(lines.utf8)), versions: versions)
    }

    /// `otool -L`, as the installer reads it: every load command after the first line.
    public static func loadedLibraries(_ path: String) throws -> [String] {
        let result = try Commands.run("/usr/bin/otool", ["-L", path])
        guard result.status == 0 else { throw Failure(description: "otool could not read \((path as NSString).lastPathComponent).") }
        return result.text.split(separator: "\n").dropFirst().compactMap { line in
            line.split(whereSeparator: { $0 == " " || $0 == "\t" }).first.map(String.init)
        }
    }

    /// The first `OpenSSL x.y.z …` string in the library, as `strings -a | grep -m1` finds it.
    static func opensslVersion(in path: String) -> String? {
        guard let data = FileManager.default.contents(atPath: path) else { return nil }
        var run = [UInt8]()
        for byte in data + [0] {
            if (0x20...0x7e).contains(byte) || byte == 0x09 { run.append(byte); continue }
            if run.count >= 4, run.starts(with: Array("OpenSSL ".utf8)) {
                let text = String(decoding: run, as: UTF8.self)
                if text.range(of: #"^OpenSSL [0-9]+\.[0-9]+\.[0-9]+"#, options: .regularExpression) != nil { return text }
            }
            run.removeAll(keepingCapacity: true)
        }
        return nil
    }

    static func realPath(_ path: String) throws -> String {
        guard let resolved = realpath(path, nil) else { throw Failure(description: "cannot resolve \(path).") }
        defer { free(resolved) }
        return String(cString: resolved)
    }

    static func sha256(of path: String) throws -> String {
        guard let data = FileManager.default.contents(atPath: path) else { throw Failure(description: "cannot read \(path).") }
        return sha256(data)
    }

    static func sha256(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    static func isSHA256(_ value: String) -> Bool {
        value.utf8.count == 64 && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }
}
