import Foundation

/// Allow-list checks on ASCII bytes. Anything outside the listed characters,
/// including every non-ASCII character, is rejected.
public enum Validation {
    /// A DNS hostname: dot-separated labels of 1–63 letters, digits or `-`, none
    /// starting or ending with `-`, at most 253 characters, no empty label (so no
    /// leading, trailing or doubled dot). The last label must not be all digits,
    /// so a malformed IPv4 address such as `010.0.0.1` is not taken for a name.
    public static func hostname(_ text: String) -> Bool {
        guard !text.isEmpty, text.utf8.count <= 253 else { return false }
        let labels = text.utf8.split(separator: dot, omittingEmptySubsequences: false)
        let labelsOK = labels.allSatisfy { label in
            (1...63).contains(label.count) && label.first != hyphen && label.last != hyphen &&
            label.allSatisfy { isDigit($0) || isLetter($0) || $0 == hyphen }
        }
        return labelsOK && !labels[labels.count - 1].allSatisfy(isDigit)
    }

    /// A dotted-quad IPv4 address: four decimal parts 0–255, written without
    /// leading zeros (`010` is octal to some parsers), signs or spaces.
    public static func ipv4(_ text: String) -> Bool {
        let parts = text.utf8.split(separator: dot, omittingEmptySubsequences: false)
        return parts.count == 4 && parts.allSatisfy { part in
            guard (1...3).contains(part.count), part.allSatisfy(isDigit) else { return false }
            guard part.count == 1 || part.first != UInt8(ascii: "0") else { return false }
            return part.reduce(0) { $0 * 10 + Int($1 - UInt8(ascii: "0")) } <= 255
        }
    }

    /// A gateway address: an IPv4 address or a hostname.
    public static func host(_ text: String) -> Bool { ipv4(text) || hostname(text) }

    /// A SHA-256 certificate fingerprint: exactly 64 lowercase hex digits.
    public static func digest(_ text: String) -> Bool {
        text.utf8.count == 64 && text.utf8.allSatisfy { isDigit($0) || (UInt8(ascii: "a")...UInt8(ascii: "f")).contains($0) }
    }

    /// An openfortivpn realm: 1–63 of `A-Z a-z 0-9 . _ -`. openfortivpn silently
    /// truncates longer realms (S3).
    public static func realm(_ text: String) -> Bool {
        (1...63).contains(text.utf8.count) && text.utf8.allSatisfy {
            isDigit($0) || isLetter($0) || $0 == dot || $0 == UInt8(ascii: "_") || $0 == hyphen
        }
    }

    private static let dot = UInt8(ascii: ".")
    private static let hyphen = UInt8(ascii: "-")
    private static func isDigit(_ byte: UInt8) -> Bool { (UInt8(ascii: "0")...UInt8(ascii: "9")).contains(byte) }
    private static func isLetter(_ byte: UInt8) -> Bool {
        (UInt8(ascii: "a")...UInt8(ascii: "z")).contains(byte) || (UInt8(ascii: "A")...UInt8(ascii: "Z")).contains(byte)
    }
}
