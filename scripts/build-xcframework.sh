#!/usr/bin/env bash
#
# Build BrairdCore.xcframework (macOS + iOS device + iOS simulator, arm64) and refresh
# the committed Swift bindings. macOS-only (xcodebuild). Run from anywhere; resolves the
# repo root itself. The xcframework is a build artifact (gitignored) — the nightly-macos
# CI job runs this, then `swift test` in bindings/swift.
set -euo pipefail

cd "$(dirname "$0")/.."
LIB=libbraird_core.a
NAME=braird_core

echo "▸ building static libs (macOS host + iOS device + iOS sim, arm64)"
cargo build --release
cargo build --release --target aarch64-apple-ios
cargo build --release --target aarch64-apple-ios-sim

echo "▸ generating Swift bindings from the library"
GEN=$(mktemp -d)
cargo run --quiet --bin uniffi-bindgen -- generate \
  --library "target/aarch64-apple-ios/release/${LIB}" \
  --language swift --out-dir "${GEN}"

# Commit-tracked Swift API source for the SwiftPM package.
mkdir -p bindings/swift/Sources/BrairdCore
cp "${GEN}/${NAME}.swift" bindings/swift/Sources/BrairdCore/BrairdCore.swift

# Headers folder for the xcframework: the C shim + a `module.modulemap` so the
# binaryTarget exposes the `braird_coreFFI` module the Swift API imports.
HDRS=$(mktemp -d)
cp "${GEN}/${NAME}FFI.h" "${HDRS}/"
cp "${GEN}/${NAME}FFI.modulemap" "${HDRS}/module.modulemap"

echo "▸ assembling BrairdCore.xcframework"
rm -rf BrairdCore.xcframework
xcodebuild -create-xcframework \
  -library "target/release/${LIB}" -headers "${HDRS}" \
  -library "target/aarch64-apple-ios/release/${LIB}" -headers "${HDRS}" \
  -library "target/aarch64-apple-ios-sim/release/${LIB}" -headers "${HDRS}" \
  -output BrairdCore.xcframework >/dev/null

echo "✓ BrairdCore.xcframework + bindings/swift/Sources/BrairdCore/BrairdCore.swift"
