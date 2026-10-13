import Testing
import Foundation
import FortiVPNShared
@testable import FortiVPNHelper

/// The real delegate and service over an anonymous XPC listener inside the test
/// process. The peer is the test runner itself: right UID, no signing certificate.
/// A caller signed with the pinned certificate being *accepted* cannot be shown
/// here; spike S1 showed it against a launchd Mach service.
struct CallerCheckTests {
    private struct Version: Equatable { let helper: String; let proto: Int; let mode: String }
    private final class Box: @unchecked Sendable {
        // @unchecked Sendable: written once from an XPC callback, read only after the semaphore is signalled.
        var version: Version?
    }

    private func ask(_ arguments: HelperLaunchArguments, clientIdentifier: String = AppIdentity.identifier) throws -> Version? {
        let check = try #require(CallerCheck(arguments: arguments, clientIdentifier: clientIdentifier))
        let listener = NSXPCListener.anonymous()
        listener.delegate = check
        listener.resume()
        defer { listener.invalidate() }
        let connection = NSXPCConnection(listenerEndpoint: listener.endpoint)
        connection.remoteObjectInterface = NSXPCInterface(with: HelperXPCProtocol.self)
        connection.resume()
        defer { connection.invalidate() }
        let finished = DispatchSemaphore(value: 0)
        let box = Box()
        let proxy = try #require(connection.remoteObjectProxyWithErrorHandler { @Sendable _ in finished.signal() } as? HelperXPCProtocol)
        proxy.version { helper, proto, mode in
            box.version = Version(helper: helper, proto: proto, mode: mode)
            finished.signal()
        }
        #expect(finished.wait(timeout: .now() + 5) == .success, "no answer and no error within 5 seconds")
        return box.version
    }

    @Test func testUIDOnlyAcceptsTheAllowedUser() throws {
        let version = try ask(try HelperLaunchArguments(allowedUID: getuid(), callerCheck: .uidOnly))
        #expect(version == Version(helper: HelperTransport.helperVersion, proto: HelperTransport.protocolVersion, mode: "uid-only"))
    }

    @Test func testAnotherUserIsRefused() throws {
        #expect(try ask(try HelperLaunchArguments(allowedUID: getuid() + 1, callerCheck: .uidOnly)) == nil)
        // Root is not special: the helper serves exactly one UID.
        if getuid() != 0 {
            #expect(try ask(try HelperLaunchArguments(allowedUID: 0, callerCheck: .uidOnly)) == nil)
        }
    }

    @Test func testSignedModeRefusesACallerWithoutThePinnedCertificate() throws {
        // The test runner is not signed with this (or any) certificate.
        let pinned = try HelperLaunchArguments(allowedUID: getuid(), callerCheck: .signed(leafSHA1: String(repeating: "0", count: 40)))
        #expect(try ask(pinned) == nil)
        // The UID check still applies in signed mode.
        let wrongUser = try HelperLaunchArguments(allowedUID: getuid() + 1, callerCheck: .signed(leafSHA1: String(repeating: "0", count: 40)))
        #expect(try ask(wrongUser) == nil)
    }

    @Test func testUnbuildableRequirementDoesNotFallBackToUIDOnly() throws {
        let signed = try HelperLaunchArguments(allowedUID: getuid(), callerCheck: .signed(leafSHA1: String(repeating: "A", count: 40)))
        #expect(CallerCheck(arguments: signed, clientIdentifier: "bad\" or anchor apple") == nil)
        #expect(CallerCheck(arguments: signed, clientIdentifier: "") == nil)
    }
}
