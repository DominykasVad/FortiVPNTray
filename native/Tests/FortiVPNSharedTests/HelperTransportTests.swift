import Testing
import Foundation
import FortiVPNShared

struct HelperTransportTests {
    private let hash = "0123456789ABCDEF0123456789ABCDEF01234567"
    private typealias Arguments = HelperLaunchArguments

    private func expectRejected(_ arguments: [String], _ fragment: String, sourceLocation: SourceLocation = #_sourceLocation) {
        do {
            _ = try Arguments(parsing: arguments)
            Issue.record("accepted \(arguments)", sourceLocation: sourceLocation)
        } catch let error as Arguments.ParseError {
            #expect(error.description.contains(fragment), "\(error.description)", sourceLocation: sourceLocation)
        } catch {
            Issue.record(error, sourceLocation: sourceLocation)
        }
    }

    @Test func testMachServiceIsTheHelperLabel() {
        #expect(HelperTransport.machServiceName == "eu.dvad.fortivpntray.helper")
        #expect(HelperTransport.protocolVersion == 1)
    }

    @Test func testSignedArgumentsParse() throws {
        let parsed = try Arguments(parsing: ["--allowed-uid", "501", "--client-req-leaf", hash])
        #expect(parsed.allowedUID == 501)
        #expect(parsed.callerCheck == .signed(leafSHA1: hash))
        #expect(parsed.callerCheck.mode == .signed)
        // Order does not matter, and a lowercase hash is normalised.
        let swapped = try Arguments(parsing: ["--client-req-leaf", hash.lowercased(), "--allowed-uid", "501"])
        #expect(swapped == parsed)
    }

    @Test func testUIDOnlyArgumentsParse() throws {
        let parsed = try Arguments(parsing: ["--uid-only", "--allowed-uid", "502"])
        #expect(parsed.allowedUID == 502)
        #expect(parsed.callerCheck == .uidOnly)
        #expect(parsed.callerCheck.mode == .uidOnly)
    }

    @Test func testBuiltArgumentsParseBack() throws {
        let signed = try Arguments(allowedUID: 501, callerCheck: .signed(leafSHA1: hash.lowercased()))
        #expect(signed.arguments == ["--allowed-uid", "501", "--client-req-leaf", hash])
        #expect(try Arguments(parsing: signed.arguments) == signed)
        let uidOnly = try Arguments(allowedUID: 502, callerCheck: .uidOnly)
        #expect(uidOnly.arguments == ["--allowed-uid", "502", "--uid-only"])
        #expect(try Arguments(parsing: uidOnly.arguments) == uidOnly)
        #expect(throws: Arguments.ParseError.self) { try Arguments(allowedUID: 501, callerCheck: .signed(leafSHA1: "abc")) }
    }

    @Test func testNothingIsDefaulted() {
        expectRejected([], "--allowed-uid is required")
        expectRejected(["--uid-only"], "--allowed-uid is required")
        expectRejected(["--client-req-leaf", hash], "--allowed-uid is required")
        // A plist that lost its mode must not start the helper in the weaker one.
        expectRejected(["--allowed-uid", "501"], "one of --client-req-leaf or --uid-only is required")
        expectRejected(["--allowed-uid", "501", "--client-req-leaf", hash, "--uid-only"], "exclude each other")
    }

    @Test func testBadUserIDsRejected() {
        for uid in ["", "abc", "-1", "+501", "501x", " 501", "5 01", "0x1f5", "4294967296", "１２"] {
            expectRejected(["--allowed-uid", uid, "--uid-only"], "is not a user id")
        }
        expectRejected(["--uid-only", "--allowed-uid"], "needs a value")
    }

    @Test func testRootUIDRejected() {
        expectRejected(["--allowed-uid", "0", "--uid-only"], "must not be 0")
        expectRejected(["--allowed-uid", "0", "--client-req-leaf", hash], "must not be 0")
        #expect(throws: Arguments.ParseError.self) { try Arguments(allowedUID: 0, callerCheck: .uidOnly) }
        #expect(throws: Arguments.ParseError.self) { try Arguments(allowedUID: 0, callerCheck: .signed(leafSHA1: hash)) }
    }

    @Test func testBadHashesRejected() {
        let bad = ["", String(hash.dropLast()), hash + "0", String(hash.dropLast()) + "G", String(hash.dropLast()) + "\"",
                   "sha1:" + String(hash.dropLast(5)), String(repeating: "é", count: 40), String(hash.dropLast()) + "\n"]
        for value in bad {
            expectRejected(["--allowed-uid", "501", "--client-req-leaf", value], "is not a 40-digit SHA-1")
        }
        expectRejected(["--allowed-uid", "501", "--client-req-leaf"], "needs a value")
    }

    @Test func testUnknownAndRepeatedArgumentsRejected() {
        expectRejected(["--allowed-uid", "501", "--uid-only", "--verbose"], "unknown argument: --verbose")
        expectRejected(["--allowed-uid", "501", "--uid-only", "extra"], "unknown argument: extra")
        expectRejected(["--allowed-uid=501", "--uid-only"], "unknown argument")
        expectRejected(["--allowed-uid", "501", "--allowed-uid", "502", "--uid-only"], "given twice")
        expectRejected(["--allowed-uid", "501", "--uid-only", "--uid-only"], "given twice")
        expectRejected(["--allowed-uid", "501", "--client-req-leaf", hash, "--client-req-leaf", hash], "given twice")
    }

    @Test func testRequirementString() {
        #expect(CallerRequirement.string(identifier: "eu.dvad.fortivpntray", leafSHA1: hash)
                == "identifier \"eu.dvad.fortivpntray\" and certificate leaf = H\"0123456789ABCDEF0123456789ABCDEF01234567\"")
        #expect(CallerRequirement.string(identifier: "eu.dvad.fortivpntray", leafSHA1: hash.lowercased())
                == CallerRequirement.string(identifier: "eu.dvad.fortivpntray", leafSHA1: hash))
    }

    @Test func testRequirementRejectsAnythingThatCouldEscapeTheString() {
        for identifier in ["", "a\" or anchor apple or identifier \"b", "a b", "a\nb", "a\\b", "a/b", "a*", "é.example"] {
            #expect(CallerRequirement.string(identifier: identifier, leafSHA1: hash) == nil, "\(identifier)")
        }
        for value in ["", String(hash.dropLast()), hash + "0", String(hash.dropLast()) + "\"", String(hash.dropLast()) + "Z"] {
            #expect(CallerRequirement.string(identifier: "eu.dvad.fortivpntray", leafSHA1: value) == nil, "\(value)")
        }
    }

    @Test func testModeTitles() {
        #expect(CallerCheckMode.signed.title == "Signed caller check")
        #expect(CallerCheckMode.uidOnly.title == "UID-only")
        #expect(CallerCheckMode(rawValue: "uid-only") == .uidOnly)
        #expect(CallerCheckMode(rawValue: "signed") == .signed)
        #expect(CallerCheckMode(rawValue: "") == nil)
    }
}
