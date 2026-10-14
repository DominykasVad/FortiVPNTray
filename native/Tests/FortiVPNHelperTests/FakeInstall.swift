import Foundation
@testable import FortiVPNHelper

/// A throwaway copy of the `<label>.d` tree and run directory in a temporary
/// directory, trusted as if the test user were root. The "openfortivpn" binary
/// is a shell script given by the test.
final class FakeInstall {
    let root: String
    let install: OpenFortiVPNInstall
    let runDirectory: RunDirectory
    /// Where the fake binary writes what it received.
    var report: String { root + "/child.out" }

    static let trust = FileTrust(trustedOwners: [0, getuid()])

    init(script: String = FakeInstall.script(), libraries: [String: String] = ["libcrypto.4.dylib": "crypto", "libssl.4.dylib": "ssl"]) throws {
        let temporary = FileManager.default.temporaryDirectory.appendingPathComponent("fvt-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: temporary, withIntermediateDirectories: false)
        root = try Self.realPath(temporary.path)
        chmod(root, 0o755)
        install = OpenFortiVPNInstall(directory: root + "/fortivpntray.helper.d", trust: Self.trust)
        runDirectory = RunDirectory(path: root + "/support/run", trust: Self.trust, owner: getuid())
        for directory in [install.directory, install.libraryDirectory, install.certsDirectory] {
            try Self.makeDirectory(directory)
        }
        try write(script.replacingOccurrences(of: "@REPORT@", with: report), to: install.binary, mode: 0o755)
        for (name, contents) in libraries {
            try write(contents, to: install.libraryDirectory + "/" + name, mode: 0o644)
        }
        try writeManifest()
    }

    deinit {
        try? FileManager.default.removeItem(atPath: root)
    }

    /// A fake openfortivpn that records its argv, environment and config file, then
    /// behaves as `then` says (shell lines, run after the report is written).
    static func script(then: String = "echo 'INFO:   Tunnel is up and running.'\nexec /bin/sleep 30") -> String {
        """
        #!/bin/sh
        {
          for arg in "$@"; do printf 'arg:%s\\n' "$arg"; done
          /usr/bin/env | /usr/bin/sort | /usr/bin/sed 's/^/env:/'
          printf 'config:\\n'
          /bin/cat "$2"
        } > "@REPORT@.tmp"
        /bin/mv "@REPORT@.tmp" "@REPORT@"
        echo 'INFO:   Connected to gateway.'
        \(then)
        """
    }

    /// Writes a manifest that matches the tree, or one changed by `edit`.
    func writeManifest(edit: (inout [[String: String]], inout String) -> Void = { _, _ in }) throws {
        let libraries = try FileManager.default.contentsOfDirectory(atPath: install.libraryDirectory)
            .sorted { $0.utf8.lexicographicallyPrecedes($1.utf8) }
        var files: [[String: String]] = []
        var setLines = ""
        for file in ["openfortivpn"] + libraries.map({ "lib/" + $0 }) {
            let hash = try OpenFortiVPNInstall.sha256(of: install.directory + "/" + file)
            files.append(["file": file, "sha256": hash, "source": "/opt/homebrew/example/" + file, "source_sha256": hash])
            setLines += "\(hash)  \(file)\n"
        }
        var setHash = OpenFortiVPNInstall.sha256(Data(setLines.utf8))
        edit(&files, &setHash)
        let manifest: [String: Any] = ["openfortivpn_version": "1.24.1", "set_sha256": setHash, "source_set_sha256": setHash, "files": files]
        let data = try JSONSerialization.data(withJSONObject: manifest, options: [.prettyPrinted, .sortedKeys])
        try? FileManager.default.removeItem(atPath: install.manifest)
        try write(String(decoding: data, as: UTF8.self), to: install.manifest, mode: 0o644)
    }

    func write(_ contents: String, to path: String, mode: mode_t) throws {
        try Data(contents.utf8).write(to: URL(fileURLWithPath: path))
        guard chmod(path, mode) == 0 else { throw POSIXError(.EPERM) }
    }

    /// Lines the fake binary reported, or nil if it has not written them within `timeout`.
    func waitForReport(timeout: TimeInterval = 10) -> [String]? {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if let text = try? String(contentsOfFile: report, encoding: .utf8) {
                return text.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
            }
            usleep(20_000)
        }
        return nil
    }

    func configFiles() -> [String] {
        (try? FileManager.default.contentsOfDirectory(atPath: runDirectory.path)) ?? []
    }

    static func makeDirectory(_ path: String) throws {
        try FileManager.default.createDirectory(atPath: path, withIntermediateDirectories: false)
        guard chmod(path, 0o755) == 0 else { throw POSIXError(.EPERM) }
    }

    static func realPath(_ path: String) throws -> String {
        guard let resolved = realpath(path, nil) else { throw POSIXError(.ENOENT) }
        defer { free(resolved) }
        return String(cString: resolved)
    }
}

/// Polls `condition` for up to `timeout` seconds.
func eventually(timeout: TimeInterval = 10, _ condition: () -> Bool) -> Bool {
    let deadline = Date().addingTimeInterval(timeout)
    while Date() < deadline {
        if condition() { return true }
        usleep(20_000)
    }
    return condition()
}

func isAlive(_ pid: pid_t) -> Bool {
    kill(pid, 0) == 0 || errno != ESRCH
}
