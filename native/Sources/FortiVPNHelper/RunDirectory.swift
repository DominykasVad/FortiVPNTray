import Foundation
import FortiVPNShared

/// The root-owned `0700` directory that holds per-session config files (PLAN.md 2.3).
/// Files are created `O_CREAT|O_EXCL|O_NOFOLLOW` with mode `0600`; nothing goes under `/tmp`.
struct RunDirectory: Sendable {
    struct Failure: Error, Equatable, CustomStringConvertible {
        let description: String
    }

    let path: String
    let trust: FileTrust
    /// Who must own the directory: root in production.
    let owner: uid_t

    static let production = RunDirectory(path: AppIdentity.helperRunDirectory, trust: .root, owner: 0)

    /// Creates the directory and its parent with mode `0700` if missing, then
    /// checks it: trusted path, owned by `owner`, mode exactly `0700`.
    func prepare() throws {
        let parent = (path as NSString).deletingLastPathComponent
        for directory in [parent, path] where mkdir(directory, 0o700) != 0 && errno != EEXIST {
            throw Failure(description: "Cannot create \(directory): \(String(cString: strerror(errno)))")
        }
        do { try trust.check(path, is: .directory) } catch let failure as FileTrust.Failure {
            throw Failure(description: failure.description)
        }
        var info = stat()
        guard lstat(path, &info) == 0, info.st_uid == owner, info.st_mode & 0o7777 == 0o700 else {
            throw Failure(description: "\(path) is not owned by uid \(owner) with mode 0700")
        }
    }

    /// Creates `name` with `contents`, mode `0600`. Fails if anything already exists at that name,
    /// including a symlink. `name` is a single component chosen by the helper.
    func create(_ name: String, contents: Data) throws -> String {
        guard !name.isEmpty, name.utf8.allSatisfy({ $0 != UInt8(ascii: "/") }), !name.hasPrefix(".") else {
            throw Failure(description: "Bad file name")
        }
        let file = path + "/" + name
        let fd = open(file, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw Failure(description: "Cannot create \(file): \(String(cString: strerror(errno)))") }
        defer { close(fd) }
        let written = contents.withUnsafeBytes { buffer in
            var offset = 0
            while offset < buffer.count {
                let result = write(fd, buffer.baseAddress! + offset, buffer.count - offset)
                if result < 0 {
                    if errno == EINTR { continue }
                    return false
                }
                offset += result
            }
            return true
        }
        guard written, fsync(fd) == 0 else {
            unlink(file)
            throw Failure(description: "Cannot write \(file): \(String(cString: strerror(errno)))")
        }
        return file
    }

    /// Removes a file this directory created. Missing is not an error.
    func remove(_ name: String) {
        unlink(path + "/" + name)
    }
}
