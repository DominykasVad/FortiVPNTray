import Foundation

/// The XPC transport between the app and the Swift root helper.
public enum HelperTransport {
    /// Mach service the helper's launchd job registers. Same as its label.
    public static let machServiceName = AppIdentity.helperLabel
    /// Bumped whenever the XPC interface changes incompatibly.
    public static let protocolVersion = 1
    /// Version of the Swift helper itself.
    public static let helperVersion = "0.3.0"
}

/// How the helper decides which callers it talks to. The raw value crosses XPC.
public enum CallerCheckMode: String, Sendable, Equatable {
    /// Allowed UID and a code-signing requirement on the app's identifier and certificate.
    case signed
    /// Allowed UID only: any process of that user is accepted. Used when the app is ad-hoc signed.
    case uidOnly = "uid-only"

    public var title: String { self == .signed ? "Signed caller check" : "UID-only" }
}

/// What the helper exposes over XPC. Task 2.2 adds the tunnel calls.
@objc public protocol HelperXPCProtocol {
    /// Replies with the helper version, the protocol version and the `CallerCheckMode` raw value.
    func version(reply: @escaping @Sendable (String, Int, String) -> Void)
}

/// The helper's launch arguments. They are written into the launchd plist at
/// install time, behind the admin prompt, and are the only source of the allowed
/// UID and the pinned certificate. The installer builds them with `arguments`
/// and the helper reads them with `init(parsing:)`, so the two cannot drift.
public struct HelperLaunchArguments: Equatable, Sendable {
    public enum CallerCheck: Equatable, Sendable {
        /// SHA-1 of the app's leaf signing certificate, 40 uppercase hex digits.
        case signed(leafSHA1: String)
        case uidOnly

        public var mode: CallerCheckMode {
            switch self {
            case .signed: return .signed
            case .uidOnly: return .uidOnly
            }
        }
    }

    public struct ParseError: Error, Equatable, CustomStringConvertible {
        public let description: String
        init(_ description: String) { self.description = description }
    }

    public static let allowedUIDFlag = "--allowed-uid"
    public static let leafFlag = "--client-req-leaf"
    public static let uidOnlyFlag = "--uid-only"

    public let allowedUID: uid_t
    public let callerCheck: CallerCheck

    /// - Throws: `ParseError` if `leafSHA1` is not 40 hex digits.
    public init(allowedUID: uid_t, callerCheck: CallerCheck) throws {
        self.allowedUID = allowedUID
        if case .signed(let hash) = callerCheck {
            self.callerCheck = .signed(leafSHA1: try Self.normalizedHash(hash))
        } else {
            self.callerCheck = callerCheck
        }
    }

    /// Arguments after the executable path, as they go into `ProgramArguments`.
    public var arguments: [String] {
        var result = [Self.allowedUIDFlag, String(allowedUID)]
        switch callerCheck {
        case .signed(let hash): result += [Self.leafFlag, hash]
        case .uidOnly: result += [Self.uidOnlyFlag]
        }
        return result
    }

    /// Parses the arguments after the executable path. Everything is required and
    /// nothing is defaulted: a missing UID, a missing mode, both modes, a repeated
    /// or unknown argument are all errors, so a damaged plist cannot quietly
    /// weaken the check.
    public init(parsing arguments: [String]) throws {
        var uid: uid_t?
        var hash: String?
        var uidOnly = false
        var index = 0
        func value(for flag: String) throws -> String {
            guard index + 1 < arguments.count else { throw ParseError("\(flag) needs a value") }
            index += 1
            return arguments[index]
        }
        while index < arguments.count {
            let flag = arguments[index]
            switch flag {
            case Self.allowedUIDFlag:
                guard uid == nil else { throw ParseError("\(flag) given twice") }
                let text = try value(for: flag)
                // Digits only: `uid_t("+501")` and similar would otherwise be accepted.
                guard !text.isEmpty, text.utf8.allSatisfy({ (48...57).contains($0) }), let parsed = uid_t(text) else {
                    throw ParseError("\(flag) is not a user id: \(text)")
                }
                uid = parsed
            case Self.leafFlag:
                guard hash == nil else { throw ParseError("\(flag) given twice") }
                hash = try Self.normalizedHash(try value(for: flag))
            case Self.uidOnlyFlag:
                guard !uidOnly else { throw ParseError("\(flag) given twice") }
                uidOnly = true
            default:
                throw ParseError("unknown argument: \(flag)")
            }
            index += 1
        }
        guard let uid else { throw ParseError("\(Self.allowedUIDFlag) is required") }
        switch (hash, uidOnly) {
        case (let hash?, false): self.callerCheck = .signed(leafSHA1: hash)
        case (nil, true): self.callerCheck = .uidOnly
        case (nil, false): throw ParseError("one of \(Self.leafFlag) or \(Self.uidOnlyFlag) is required")
        case (_?, true): throw ParseError("\(Self.leafFlag) and \(Self.uidOnlyFlag) exclude each other")
        }
        self.allowedUID = uid
    }

    private static func normalizedHash(_ text: String) throws -> String {
        guard text.utf8.count == 40, text.utf8.allSatisfy({ (48...57).contains($0) || (65...70).contains($0) || (97...102).contains($0) }) else {
            throw ParseError("\(leafFlag) is not a 40-digit SHA-1")
        }
        return text.uppercased()
    }
}

/// The code-signing requirement the helper sets on every incoming connection in signed mode.
public enum CallerRequirement {
    /// `identifier "<id>" and certificate leaf = H"<sha1>"`.
    /// Returns nil unless the identifier is a plain reverse-DNS name and the hash is 40 hex digits:
    /// both are placed inside a requirement string, so neither may contain a quote or anything else.
    public static func string(identifier: String, leafSHA1: String) -> String? {
        let identifierOK = !identifier.isEmpty && identifier.utf8.allSatisfy {
            (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || $0 == 45 || $0 == 46
        }
        let hashOK = leafSHA1.utf8.count == 40 && leafSHA1.utf8.allSatisfy {
            (48...57).contains($0) || (65...70).contains($0) || (97...102).contains($0)
        }
        guard identifierOK, hashOK else { return nil }
        return "identifier \"\(identifier)\" and certificate leaf = H\"\(leafSHA1.uppercased())\""
    }
}
