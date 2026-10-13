// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "FortiVPNTray",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "FortiVPNCore", targets: ["FortiVPNCore"]),
        .executable(name: "FortiVPNTray", targets: ["FortiVPNTray"])
    ],
    targets: [
        .target(name: "FortiVPNShared"),
        .target(name: "FortiVPNCore", dependencies: ["FortiVPNShared"]),
        .executableTarget(name: "FortiVPNTray", dependencies: ["FortiVPNCore", "FortiVPNShared"]),
        .testTarget(name: "FortiVPNSharedTests", dependencies: ["FortiVPNShared"]),
        .testTarget(name: "FortiVPNCoreTests", dependencies: ["FortiVPNCore", "FortiVPNShared"])
    ],
    swiftLanguageModes: [.v6]
)
