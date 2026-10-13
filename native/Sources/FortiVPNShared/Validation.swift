import Foundation

public enum Validation {
    public static func hostname(_ text: String) -> Bool {
        !text.isEmpty && text.count <= 253 && text.first != "-" && text.first != "." &&
        text.utf8.allSatisfy { (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || $0 == 45 || $0 == 46 }
    }
    public static func ipv4(_ text: String) -> Bool {
        let parts = text.split(separator: ".", omittingEmptySubsequences: false)
        return parts.count == 4 && parts.allSatisfy { !$0.isEmpty && $0.allSatisfy(\.isNumber) && UInt8($0) != nil }
    }
    public static func digest(_ text: String) -> Bool { text.count == 64 && text.utf8.allSatisfy { (48...57).contains($0) || (65...70).contains($0) || (97...102).contains($0) } }
}
