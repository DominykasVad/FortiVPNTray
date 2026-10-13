// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "FortiVPNTray",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "FortiVPNCore", targets: ["FortiVPNCore"]),
        .executable(name: "FortiVPNTray", targets: ["FortiVPNTray"]),
        .executable(name: "FortiVPNHelper", targets: ["FortiVPNHelper"])
    ],
    targets: [
        .target(name: "FortiVPNShared"),
        .target(name: "FortiVPNCore", dependencies: ["FortiVPNShared"]),
        .executableTarget(name: "FortiVPNTray", dependencies: ["FortiVPNCore", "FortiVPNShared"]),
        .executableTarget(name: "FortiVPNHelper", dependencies: ["FortiVPNShared"]),
        .testTarget(name: "FortiVPNSharedTests", dependencies: ["FortiVPNShared"]),
        .testTarget(name: "FortiVPNCoreTests", dependencies: ["FortiVPNCore", "FortiVPNShared"]),
        .testTarget(name: "FortiVPNHelperTests", dependencies: ["FortiVPNHelper", "FortiVPNShared"])
    ],
    swiftLanguageModes: [.v6]
)
