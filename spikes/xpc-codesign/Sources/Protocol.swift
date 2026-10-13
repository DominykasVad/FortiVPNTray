import Foundation

/// The whole interface of the spike: one call that says who the daemon thinks is calling.
@objc protocol SpikeProtocol {
    func whoAmI(reply: @escaping @Sendable (String) -> Void)
}
