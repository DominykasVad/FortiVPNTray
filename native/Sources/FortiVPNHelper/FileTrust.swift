import Foundation

/// Decides whether root may execute, load or write in a path (PLAN.md 2.3, F3).
///
/// The path and every directory above it, up to `/`, must be owned by a trusted
/// owner (root in production), not group- or other-writable, and not a symlink.
/// Nobody else can then replace anything on the way between this check and its use.
struct FileTrust: Sendable {
    enum Kind: Sendable { case file, directory }

    struct Failure: Error, Equatable, CustomStringConvertible {
        let description: String
    }

    let trustedOwners: Set<uid_t>

    static let root = FileTrust(trustedOwners: [0])

    func check(_ path: String, is kind: Kind) throws {
        // Only canonical absolute paths: no "." or "..", no empty component, no trailing slash.
        let components = path.split(separator: "/", omittingEmptySubsequences: false).dropFirst()
        guard path.hasPrefix("/"), path == "/" || components.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." }) else {
            throw Failure(description: "\(path) is not a canonical absolute path")
        }
        var prefixes = ["/"]
        var current = ""
        for component in components where path != "/" {
            current += "/" + component
            prefixes.append(current)
        }
        for (index, prefix) in prefixes.enumerated() {
            var info = stat()
            guard lstat(prefix, &info) == 0 else {
                throw Failure(description: "\(prefix): \(String(cString: strerror(errno)))")
            }
            let type = info.st_mode & S_IFMT
            guard type != S_IFLNK else { throw Failure(description: "\(prefix) is a symlink") }
            guard trustedOwners.contains(info.st_uid) else {
                throw Failure(description: "\(prefix) is owned by uid \(info.st_uid)")
            }
            guard info.st_mode & (S_IWGRP | S_IWOTH) == 0 else {
                throw Failure(description: "\(prefix) is group or other writable")
            }
            let isLast = index == prefixes.count - 1
            let wanted = isLast && kind == .file ? S_IFREG : S_IFDIR
            guard type == wanted else {
                throw Failure(description: "\(prefix) is not a \(wanted == S_IFREG ? "regular file" : "directory")")
            }
        }
    }
}
