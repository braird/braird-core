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

# Refresh the COMMITTED Kotlin + Swift bindings via the single canonical generator (DRY,
# --no-format) — same script the `bindings-drift` CI guard runs, so this can never drift
# from CI. The binding text is target-independent, so generating from the release host lib
# here matches CI's debug-host generation byte-for-byte.
echo "▸ refreshing committed bindings (scripts/gen-bindings.sh)"
scripts/gen-bindings.sh release

# The xcframework additionally needs the C shim header + modulemap (NOT committed — only
# live inside the gitignored xcframework), generated here from the iOS device lib.
echo "▸ generating FFI header + modulemap for the xcframework"
GEN=$(mktemp -d)
cargo run --quiet --bin uniffi-bindgen -- generate \
  --library "target/aarch64-apple-ios/release/${LIB}" \
  --language swift --no-format --out-dir "${GEN}"
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
