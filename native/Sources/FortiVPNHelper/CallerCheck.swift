import Foundation
import FortiVPNShared
import os

/// Decides which XPC connections the helper accepts (PLAN.md 2.1, finding F1).
///
/// Every connection must come from the allowed UID. In signed mode the system
/// additionally checks the caller's code signature against the requirement:
/// a caller that does not satisfy it has its messages dropped and the
/// connection invalidated before anything reaches the exported object.
final class CallerCheck: NSObject, NSXPCListenerDelegate {
    private let allowedUID: uid_t
    private let requirement: String?
    private let mode: CallerCheckMode
    private let sessions: SessionController
    private let log = Logger(subsystem: AppIdentity.helperLabel, category: "caller-check")

    /// Fails if a signed-mode requirement cannot be built, rather than falling back to UID-only.
    init?(arguments: HelperLaunchArguments, sessions: SessionController, clientIdentifier: String = AppIdentity.identifier) {
        allowedUID = arguments.allowedUID
        self.sessions = sessions
        mode = arguments.callerCheck.mode
        switch arguments.callerCheck {
        case .signed(let leafSHA1):
            guard let requirement = CallerRequirement.string(identifier: clientIdentifier, leafSHA1: leafSHA1) else { return nil }
            self.requirement = requirement
        case .uidOnly:
            requirement = nil
        }
    }

    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        let uid = connection.effectiveUserIdentifier
        guard uid == allowedUID else {
            log.notice("Refused pid \(connection.processIdentifier, privacy: .public): uid \(uid, privacy: .public) is not the allowed uid")
            return false
        }
        if let requirement {
            connection.setCodeSigningRequirement(requirement)
        }
        connection.exportedInterface = NSXPCInterface(with: HelperXPCProtocol.self)
        connection.exportedObject = HelperService(mode: mode, sessions: sessions)
        connection.resume()
        return true
    }
}
