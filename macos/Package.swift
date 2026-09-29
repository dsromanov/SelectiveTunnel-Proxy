// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "SelectiveTunnel",
    platforms: [.macOS(.v13)],
    targets: [
        .target(
            name: "STCore",
            path: "Sources/STCore"
        ),
        .executableTarget(
            name: "SelectiveTunnelDaemon",
            dependencies: ["STCore"],
            path: "Sources/SelectiveTunnelDaemon"
        ),
        .executableTarget(
            name: "SelectiveTunnel",
            dependencies: ["STCore"],
            path: "Sources/SelectiveTunnel"
        ),
    ]
)
