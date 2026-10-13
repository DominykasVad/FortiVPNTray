import Foundation
import FortiVPNShared

/// The object exported to accepted callers. Task 2.2 adds the tunnel calls.
final class HelperService: NSObject, HelperXPCProtocol {
    private let mode: CallerCheckMode

    init(mode: CallerCheckMode) {
        self.mode = mode
    }

    func version(reply: @escaping @Sendable (String, Int, String) -> Void) {
        reply(HelperTransport.helperVersion, HelperTransport.protocolVersion, mode.rawValue)
    }
}
