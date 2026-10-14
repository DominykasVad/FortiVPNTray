import CryptoKit
import Foundation
import FortiVPNShared

/// The root-owned copy of openfortivpn and its dylibs (S2), checked before every spawn.
///
/// Layout, written by the installer (2.6):
///
///     <directory>/openfortivpn       the binary
///     <directory>/lib/*.dylib        every non-system library it loads
///     <directory>/certs/             empty; the child's SSL_CERT_DIR
///     <directory>/manifest.json      sha256 of each file and of the set
///
/// The set hash is the sha256 of one `<sha256>  <file>\n` line per file: the
/// binary first, then the libraries sorted by name (as S2's `copy.sh` writes it).
struct OpenFortiVPNInstall: Sendable {
    struct Failure: Error, Equatable, CustomStringConvertible {
        let description: String
    }

    let directory: String
    let trust: FileTrust

    static let production = OpenFortiVPNInstall(directory: AppIdentity.openfortivpnDirectory, trust: .root)

    var binary: String { directory + "/openfortivpn" }
    var libraryDirectory: String { directory + "/lib" }
    /// Empty and root-owned, so OpenSSL finds no CA here (decision log, 2.3).
    var certsDirectory: String { directory + "/certs" }
    /// Never exists: `lib/` may hold only the files in the manifest, so OpenSSL loads no provider module.
    var modulesDirectory: String { libraryDirectory + "/ossl-modules" }
    var manifest: String { directory + "/manifest.json" }

    private struct Manifest: Decodable {
        struct Entry: Decodable {
            let file: String
            let sha256: String
        }
        let set_sha256: String
        let files: [Entry]
    }

    private static let maxManifestSize = 1 << 20

    /// Refuses unless every file is trusted, matches the manifest, and nothing else is present.
    func verify() throws {
        do {
            for path in [directory, libraryDirectory, certsDirectory] { try trust.check(path, is: .directory) }
            try trust.check(manifest, is: .file)
            try trust.check(binary, is: .file)
        } catch let failure as FileTrust.Failure {
            throw Failure(description: failure.description)
        }
        guard try FileManager.default.contentsOfDirectory(atPath: certsDirectory).isEmpty else {
            throw Failure(description: "\(certsDirectory) is not empty")
        }
        let libraries = try FileManager.default.contentsOfDirectory(atPath: libraryDirectory).sorted { $0.utf8.lexicographicallyPrecedes($1.utf8) }
        let present = ["openfortivpn"] + libraries.map { "lib/" + $0 }

        let data = try Data(contentsOf: URL(fileURLWithPath: manifest))
        guard data.count <= Self.maxManifestSize, let parsed = try? JSONDecoder().decode(Manifest.self, from: data) else {
            throw Failure(description: "\(manifest) is not a valid manifest")
        }
        var recorded: [String: String] = [:]
        for entry in parsed.files {
            guard recorded.updateValue(entry.sha256, forKey: entry.file) == nil else {
                throw Failure(description: "the manifest lists \(entry.file) twice")
            }
        }
        guard Set(recorded.keys) == Set(present) else {
            throw Failure(description: "the files present do not match the manifest")
        }

        var setLines = ""
        for file in present {
            let path = directory + "/" + file
            do { try trust.check(path, is: .file) } catch let failure as FileTrust.Failure {
                throw Failure(description: failure.description)
            }
            let hash = try Self.sha256(of: path)
            guard recorded[file] == hash else { throw Failure(description: "\(file) does not match the manifest") }
            setLines += "\(hash)  \(file)\n"
        }
        guard Self.sha256(Data(setLines.utf8)) == parsed.set_sha256 else {
            throw Failure(description: "the file set does not match the manifest")
        }
    }

    static func sha256(of path: String) throws -> String {
        sha256(try Data(contentsOf: URL(fileURLWithPath: path)))
    }

    static func sha256(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}
