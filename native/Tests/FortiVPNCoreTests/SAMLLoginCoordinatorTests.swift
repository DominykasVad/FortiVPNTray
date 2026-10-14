import Testing
import Foundation
import FortiVPNShared
@testable import FortiVPNCore

/// Where the SAML login page opens (PLAN.md 3.5).
@MainActor
struct SAMLLoginCoordinatorTests {
    @MainActor final class FakeWindow: SAMLLoginWindow {
        var opened: [URL] = []
        var closes = 0
        var closedByUser: (@MainActor () -> Void)?
        func open(_ url: URL, closedByUser: @escaping @MainActor () -> Void) {
            opened.append(url)
            self.closedByUser = closedByUser
        }
        func close() { closes += 1 }
        /// The user closes the window; the real window reports this once.
        func userCloses() { closedByUser?() }
    }

    @MainActor final class Harness {
        let window = FakeWindow()
        var browser: [URL] = []
        var cancels = 0
        var coordinator: SAMLLoginCoordinator!
        init() {
            coordinator = SAMLLoginCoordinator(window: window) { [unowned self] in self.browser.append($0) }
            coordinator.onUserCancel = { [unowned self] in self.cancels += 1 }
        }
    }

    private let url = URL(string: "https://vpn.example.com:10443/remote/saml/start?redirect=1")!

    private func profile(external: Bool = false) -> VPNProfile {
        var p = VPNProfile()
        p.name = "Office"; p.host = "vpn.example.com"; p.port = 10443; p.samlExternalBrowser = external
        return p
    }

    @Test func testDefaultOpensTheLoginWindow() {
        let h = Harness()
        #expect(h.coordinator.present(url, for: profile()) == .window)
        #expect(h.window.opened == [url])
        #expect(h.browser.isEmpty)
        #expect(h.coordinator.isWindowOpen)
    }

    @Test func testExternalBrowserWhenTheProfileSaysSo() {
        let h = Harness()
        #expect(h.coordinator.present(url, for: profile(external: true)) == .browser)
        #expect(h.browser == [url])
        #expect(h.window.opened.isEmpty)
    }

    @Test func testAnUnexpectedURLIsOpenedNowhere() {
        for external in [false, true] {
            let h = Harness()
            for bad in ["https://attacker.example.net:10443/remote/saml/start?redirect=1", "http://vpn.example.com:10443/remote/saml/start",
                        "https://vpn.example.com:443/remote/saml/start"] {
                #expect(h.coordinator.present(URL(string: bad)!, for: profile(external: external)) == .refused)
            }
            #expect(h.window.opened.isEmpty && h.browser.isEmpty)
        }
    }

    /// Connected, disconnected or failed: the app closes the window, which is not a user cancel.
    @Test func testFinishClosesTheWindowWithoutCancelling() {
        let h = Harness()
        _ = h.coordinator.present(url, for: profile())
        h.coordinator.finish()
        #expect(h.window.closes == 1)
        #expect(!h.coordinator.isWindowOpen)
        h.window.userCloses()   // A late report from the real window after close().
        #expect(h.cancels == 0)
        h.coordinator.finish()
        #expect(h.window.closes == 1, "nothing open: nothing to close")
    }

    @Test func testTheUserClosingTheWindowCancels() {
        let h = Harness()
        _ = h.coordinator.present(url, for: profile())
        h.window.userCloses()
        #expect(h.cancels == 1)
        #expect(!h.coordinator.isWindowOpen)
        h.window.userCloses()
        #expect(h.cancels == 1, "reported once")
        h.coordinator.finish()
        #expect(h.window.closes == 0)
    }

    @Test func testANewLoginReplacesTheOpenWindow() {
        let h = Harness()
        _ = h.coordinator.present(url, for: profile())
        _ = h.coordinator.present(url, for: profile())
        #expect(h.window.closes == 1)
        #expect(h.window.opened.count == 2)
        #expect(h.cancels == 0)
    }

    @Test func testTheSettingDecodesWithItsDefaultAndRoundTrips() throws {
        let old = #"[{"id":"old-id","name":"Office","host":"vpn.example.com","port":8443,"trusted_certs":[]}]"#
        let values = try JSONDecoder().decode([VPNProfile].self, from: Data(old.utf8))
        #expect(values[0].samlExternalBrowser == false)
        var external = values[0]
        external.samlExternalBrowser = true
        let encoded = try JSONEncoder().encode([external])
        #expect(String(decoding: encoded, as: UTF8.self).contains("\"saml_external_browser\":true"))
        #expect(try JSONDecoder().decode([VPNProfile].self, from: encoded) == [external])
    }

    /// App-side only: the helper's request is the same either way.
    @Test func testTheSettingIsNeverSentToTheHelper() async throws {
        var requests: [ConnectRequest] = []
        for external in [false, true] {
            let helper = FakeHelperAPI()
            try await VPNEngine(helper: helper).start(profile: profile(external: external), settings: AppSettings())
            requests += helper.requests
        }
        #expect(requests.count == 2 && requests[0] == requests[1])
        #expect(!String(decoding: requests[0].json(), as: UTF8.self).lowercased().contains("browser"))
    }
}
