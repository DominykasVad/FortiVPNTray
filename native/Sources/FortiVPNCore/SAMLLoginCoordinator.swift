import Foundation

/// The app's own SAML login window (PLAN.md 3.5). The real one is an
/// `ASWebAuthenticationSession`; tests use a fake.
@MainActor
public protocol SAMLLoginWindow: AnyObject {
    /// Shows `url`. `closedByUser` is called if the user closes the window.
    func open(_ url: URL, closedByUser: @escaping @MainActor () -> Void)
    /// Closes the window without calling `closedByUser`.
    func close()
}

/// Opens the SAML login page where the profile says: the app's login window (default)
/// or the default browser. Either way only a URL that passes `SAMLLogin.isExpected`
/// for the profile is opened. The browser's redirect to openfortivpn's local listener
/// completes the login in both cases; the app learns of it from the helper's status.
@MainActor
public final class SAMLLoginCoordinator {
    public enum Outcome: Equatable, Sendable {
        case window, browser, refused
    }

    private let window: any SAMLLoginWindow
    private let openInBrowser: @MainActor (URL) -> Void
    /// Called when the user closes the login window before the tunnel came up.
    public var onUserCancel: @MainActor () -> Void = {}
    public private(set) var isWindowOpen = false

    public init(window: any SAMLLoginWindow, openInBrowser: @escaping @MainActor (URL) -> Void) {
        self.window = window
        self.openInBrowser = openInBrowser
    }

    public func present(_ url: URL, for profile: VPNProfile) -> Outcome {
        guard let validated = try? profile.validated(), SAMLLogin.isExpected(url, host: validated.host, port: validated.port) else {
            return .refused
        }
        if validated.samlExternalBrowser {
            openInBrowser(url)
            return .browser
        }
        finish()
        isWindowOpen = true
        window.open(url) { [weak self] in
            guard let self, self.isWindowOpen else { return }
            self.isWindowOpen = false
            self.onUserCancel()
        }
        return .window
    }

    /// The tunnel is up, the session ended, or the attempt failed: the window goes.
    public func finish() {
        guard isWindowOpen else { return }
        isWindowOpen = false
        window.close()
    }
}
