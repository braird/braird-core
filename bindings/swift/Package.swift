// swift-tools-version:5.9
import PackageDescription

// Consumes the BrairdCore.xcframework produced by scripts/build-xcframework.sh (run
// that first — the xcframework is a gitignored build artifact). The generated Swift
// API (Sources/BrairdCore/BrairdCore.swift) imports the `braird_coreFFI` module that
// the xcframework's static-lib slice + module.modulemap provide.
let package = Package(
    name: "BrairdCore",
    platforms: [.macOS(.v12), .iOS(.v15)],
    products: [
        .library(name: "BrairdCore", targets: ["BrairdCore"]),
    ],
    targets: [
        .binaryTarget(name: "braird_coreFFI", path: "../../BrairdCore.xcframework"),
        .target(name: "BrairdCore", dependencies: ["braird_coreFFI"]),
        .testTarget(name: "BrairdCoreTests", dependencies: ["BrairdCore"]),
    ]
)
