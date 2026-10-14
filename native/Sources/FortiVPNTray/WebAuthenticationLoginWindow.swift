import AppKit
import AuthenticationServices
import FortiVPNCore

/// The SAML login window (PLAN.md 3.5): an `ASWebAuthenticationSession`, which needs no
/// entitlement. It is not ephemeral, so the Safari/Entra sign-in and "stay signed in" are
/// shared. The login ends with a redirect to openfortivpn's local listener
/// (`http://127.0.0.1:<port>`), which the window loads like any page; the session never
/// completes by itself, and the app closes it once the helper reports the tunnel up.
@MainActor
final class WebAuthenticationLoginWindow: NSObject, SAMLLoginWindow, ASWebAuthenticationPresentationContextProviding {
    /// Never reached: the login ends at openfortivpn's listener, not at a callback URL.
    private static let unusedCallbackScheme = "eu.dvad.fortivpntray.saml"
    private var session: ASWebAuthenticationSession?

    func open(_ url: URL, closedByUser: @escaping @MainActor () -> Void) {
        close()
        let session = ASWebAuthenticationSession(url: url, callbackURLScheme: Self.unusedCallbackScheme) { [weak self] _, error in
            // Called once: after the user closes the window, or after `close()`.
            let cancelled = (error as? ASWebAuthenticationSessionError)?.code == .canceledLogin
            Task { @MainActor in
                guard let self, self.session != nil else { return }
                self.session = nil
                if cancelled { closedByUser() }
            }
        }
        session.prefersEphemeralWebBrowserSession = false
        session.presentationContextProvider = self
        self.session = session
        NSApp.activate(ignoringOtherApps: true)
        if !session.start() {
            self.session = nil
            closedByUser()
        }
    }

    func close() {
        guard let session else { return }
        // Cleared first, so the completion handler does not report a user cancel.
        self.session = nil
        session.cancel()
    }

    nonisolated func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        MainActor.assumeIsolated {
            NSApp.windows.first { $0.isVisible && $0.canBecomeKey } ?? NSApp.windows.first ?? NSWindow()
        }
    }
}
