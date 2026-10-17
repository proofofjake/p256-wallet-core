// swift-tools-version: 5.9
// The core for Swift. Run scripts/build-swift.sh first: it builds the XCFramework and the generated bindings
// (both gitignored) from the Rust source in this repo.
import PackageDescription

let package = Package(
    name: "P256WalletCore",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [
        .library(name: "P256WalletCore", targets: ["P256WalletCore"]),
    ],
    targets: [
        .binaryTarget(name: "P256WalletCoreFFI", path: "P256WalletCoreFFI.xcframework"),
        .target(name: "P256WalletCore", dependencies: ["P256WalletCoreFFI"], path: "Sources/P256WalletCore"),
        .testTarget(name: "P256WalletCoreTests", dependencies: ["P256WalletCore"], path: "Tests/P256WalletCoreTests"),
    ]
)
