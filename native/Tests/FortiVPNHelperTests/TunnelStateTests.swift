import Testing
import Foundation
import FortiVPNShared
@testable import FortiVPNHelper

/// The state file (PLAN.md 2.5): atomic writes, strict reads, nothing trusted that is not valid.
struct TunnelStateTests {
    static let sessionID = "6F0E6A5C-8E4B-4C1E-9D7A-2B3C4D5E6F70"

    static var full: TunnelState {
        var state = TunnelState(sessionID: sessionID, serverIP: "198.51.100.7", gateway: "192.0.2.1")
        state.openfortivpn = ProcessIdentity(pid: 4242, startSeconds: 1_700_000_000, startMicroseconds: 123_456,
                                             executable: "/Library/PrivilegedHelperTools/eu.dvad.fortivpntray.helper.d/openfortivpn")
        state.pppd = ProcessIdentity(pid: 4243, startSeconds: 1_700_000_010, startMicroseconds: 0, executable: "/usr/sbin/pppd")
        state.interface = "ppp0"
        state.dnsApplied = true
        return state
    }

    private func json(_ edit: (inout [String: Any]) -> Void) throws -> Data {
        var object = try #require(try JSONSerialization.jsonObject(with: Self.full.encoded()) as? [String: Any])
        edit(&object)
        return try JSONSerialization.data(withJSONObject: object)
    }

    private func rejected(_ data: Data) -> Bool {
        (try? TunnelState.decode(data)) == nil
    }

    @Test func testRoundTrip() throws {
        #expect(try TunnelState.decode(Self.full.encoded()) == Self.full)
        let minimal = TunnelState(sessionID: Self.sessionID, serverIP: nil, gateway: nil)
        #expect(try TunnelState.decode(minimal.encoded()) == minimal)
    }

    @Test func testUnknownMissingOrBadValuesAreRejected() throws {
        #expect(rejected(try json { $0["extra"] = 1 }))
        #expect(rejected(try json { $0["sessionID"] = nil }))
        #expect(rejected(try json { $0["dnsApplied"] = nil }))
        #expect(rejected(try json { $0["sessionID"] = "../../etc" }))
        #expect(rejected(try json { $0["dnsApplied"] = "yes" }))
        for interface in ["en0", "ppp", "ppp0;", "ppp0 ", "ppp12345", "-ppp0", "utun3"] {
            #expect(rejected(try json { $0["interface"] = interface }), "\(interface)")
        }
        for address in ["192.0.2.1 ", "192.0.2", "-host", "vpn.example.com", "192.0.2.01"] {
            #expect(rejected(try json { $0["serverIP"] = address }), "\(address)")
            #expect(rejected(try json { $0["gateway"] = address }), "\(address)")
        }
        #expect(rejected(Data("[]".utf8)))
        #expect(rejected(Data("not json".utf8)))
    }

    @Test func testIdentitiesAreCheckedStrictly() throws {
        func identity(_ edit: @escaping (inout [String: Any]) -> Void) throws -> Data {
            try json { object in
                var pppd = object["pppd"] as! [String: Any]
                edit(&pppd)
                object["pppd"] = pppd
            }
        }
        #expect(rejected(try identity { $0["extra"] = 1 }))
        #expect(rejected(try identity { $0["executable"] = nil }))
        #expect(rejected(try identity { $0["pid"] = 1 }), "launchd is never a recorded process")
        #expect(rejected(try identity { $0["pid"] = 0 }))
        #expect(rejected(try identity { $0["pid"] = -5 }))
        #expect(rejected(try identity { $0["startMicroseconds"] = 1_000_000 }))
        #expect(rejected(try identity { $0["executable"] = "pppd" }))
        #expect(rejected(try identity { $0["executable"] = "" }))
        #expect(rejected(try json { $0["pppd"] = "4243" }))
    }

    @Test func testOversizedStateIsRejected() throws {
        let padded = try json { $0["interface"] = nil }
        var text = String(decoding: padded, as: UTF8.self)
        text.removeLast()
        text += String(repeating: " ", count: StateStore.maxSize) + "}"
        #expect(rejected(Data(text.utf8)))
    }

    // MARK: Store

    @Test func testSaveLoadAndClear() throws {
        let temporary = try TemporaryStateStore()
        let store = temporary.store
        #expect(try store.load() == nil)
        try store.save(Self.full)
        #expect(try store.load() == Self.full)
        var info = stat()
        #expect(lstat(store.path, &info) == 0 && info.st_mode & 0o7777 == 0o600 && info.st_mode & S_IFMT == S_IFREG)
        #expect(lstat(store.directory.path, &info) == 0 && info.st_mode & 0o7777 == 0o700)
        var changed = Self.full
        changed.dnsApplied = false
        try store.save(changed)
        #expect(try store.load() == changed)
        #expect(try FileManager.default.contentsOfDirectory(atPath: store.directory.path) == [StateStore.fileName], "no temporary file left")
        store.clear()
        store.clear()
        #expect(try store.load() == nil)
    }

    @Test func testALeftoverTemporaryFileOrLinkDoesNotRedirectTheWrite() throws {
        let temporary = try TemporaryStateStore()
        let store = temporary.store
        try store.directory.prepare()
        let target = temporary.root + "/elsewhere"
        try FileManager.default.createSymbolicLink(atPath: store.directory.path + "/" + StateStore.temporaryName, withDestinationPath: target)
        try store.save(Self.full)
        #expect(!FileManager.default.fileExists(atPath: target))
        #expect(try store.load() == Self.full)
    }

    @Test func testUnsafeStateFilesAreNotRead() throws {
        let linked = try TemporaryStateStore()
        try linked.store.directory.prepare()
        let real = linked.root + "/real.json"
        try Self.full.encoded().write(to: URL(fileURLWithPath: real))
        chmod(real, 0o600)
        try FileManager.default.createSymbolicLink(atPath: linked.store.path, withDestinationPath: real)
        #expect(throws: StateStore.Failure.self) { try linked.store.load() }

        let readable = try TemporaryStateStore()
        try readable.store.save(Self.full)
        chmod(readable.store.path, 0o644)
        #expect(throws: StateStore.Failure.self) { try readable.store.load() }

        let garbage = try TemporaryStateStore()
        try garbage.store.save(Self.full)
        try Data("{\"sessionID\": 1}".utf8).write(to: URL(fileURLWithPath: garbage.store.path))
        #expect(throws: StateStore.Failure(description: "The state file is not valid.")) { try garbage.store.load() }

        let open = try TemporaryStateStore()
        try open.store.directory.prepare()
        chmod(open.store.directory.path, 0o755)
        #expect(throws: (any Error).self) { try open.store.load() }
        #expect(throws: (any Error).self) { try open.store.save(Self.full) }
    }

    @Test func testProductionPath() {
        #expect(StateStore.production.path == "/Library/Application Support/eu.dvad.fortivpntray.helper/state.json")
        #expect(StateStore.production.path == AppIdentity.helperStateFile, "the uninstaller checks this file")
        #expect(StateStore.production.directory.owner == 0)
        #expect(StateStore.production.directory.trust.trustedOwners == [0])
    }
}
