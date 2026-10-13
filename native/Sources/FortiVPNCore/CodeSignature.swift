import Foundation
import Security
import CryptoKit

/// Reads the leaf signing certificate out of a code signature. The app uses it
/// on itself to tell the helper installer which certificate to pin; the hash is
/// derived this way and never stored or typed (PLAN.md 2.1).
public enum CodeSignature {
    /// SHA-1 of the leaf certificate that signed the running program, as 40 uppercase
    /// hex digits, or nil if it is ad-hoc signed or unsigned.
    public static func leafSHA1OfRunningCode() -> String? {
        var code: SecCode?
        guard SecCodeCopySelf(SecCSFlags(), &code) == errSecSuccess, let code else { return nil }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, SecCSFlags(), &staticCode) == errSecSuccess, let staticCode else { return nil }
        return leafSHA1(of: staticCode)
    }

    /// The same for a signed file or bundle on disk.
    public static func leafSHA1(ofCodeAt url: URL) -> String? {
        var staticCode: SecStaticCode?
        guard SecStaticCodeCreateWithPath(url as CFURL, SecCSFlags(), &staticCode) == errSecSuccess, let staticCode else { return nil }
        return leafSHA1(of: staticCode)
    }

    private static func leafSHA1(of code: SecStaticCode) -> String? {
        var information: CFDictionary?
        guard SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &information) == errSecSuccess,
              let dictionary = information as? [String: Any],
              let certificates = dictionary[kSecCodeInfoCertificates as String] as? [SecCertificate],
              let leaf = certificates.first else { return nil }
        return sha1Hex(SecCertificateCopyData(leaf) as Data)
    }

    static func sha1Hex(_ data: Data) -> String {
        Insecure.SHA1.hash(data: data).map { String(format: "%02X", $0) }.joined()
    }
}
