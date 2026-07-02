#!/usr/bin/env bash
#
# gen-bindings.sh — the single canonical UniFFI bindgen invocation (SUR-742).
#
# Regenerates the COMMITTED Kotlin + Swift bindings from the compiled library, in
# UniFFI **library mode**, with formatting **disabled** (`--no-format`). Disabling the
# formatter is load-bearing: ktlint / swiftformat versions differ across dev machines and
# CI, and a formatter re-run would rewrite the committed files into a spurious diff that the
# `bindings-drift` guard (parity.yml) would then fail on. With `--no-format`, the committed
# state is exactly what this script emits — deterministic and host-agnostic (library-mode
# generation reads the crate's embedded metadata, not any host SDK).
#
# Run this after ANY change to the FFI surface — a new/changed `#[uniffi::export]` item OR
# its docstring — then commit the regenerated bindings. `build-xcframework.sh` delegates its
# committed-binding generation here (DRY); the `bindings-drift` CI job runs this into a temp
# dir and `git diff --exit-code`s it against the committed tree.
#
# Usage:  scripts/gen-bindings.sh [debug|release]   (default: debug — faster; the generated
#         binding text is identical either way, it derives from metadata, not codegen).
set -euo pipefail

cd "$(dirname "$0")/.."

NAME=braird_core
PROFILE="${1:-debug}"

if [ "$PROFILE" = "release" ]; then
  cargo build --release
  TARGET_DIR="target/release"
else
  cargo build
  TARGET_DIR="target/debug"
fi

# Resolve the built dynamic library across hosts (Linux .so / macOS .dylib / Windows .dll).
LIB=""
for cand in "lib${NAME}.so" "lib${NAME}.dylib" "${NAME}.dll"; do
  if [ -f "${TARGET_DIR}/${cand}" ]; then LIB="${TARGET_DIR}/${cand}"; break; fi
done
if [ -z "$LIB" ]; then
  echo "gen-bindings: no cdylib for '${NAME}' in ${TARGET_DIR} — is crate-type=cdylib built?" >&2
  exit 1
fi

GEN="$(mktemp -d)"
trap 'rm -rf "$GEN"' EXIT

# Two single-language invocations (the already-built bin is reused; negligible overhead) —
# unambiguous across UniFFI point releases. `--no-format` on both for determinism.
cargo run --quiet --bin uniffi-bindgen -- generate \
  --library "$LIB" --language kotlin --no-format --out-dir "$GEN"
cargo run --quiet --bin uniffi-bindgen -- generate \
  --library "$LIB" --language swift  --no-format --out-dir "$GEN"

# Copy into the committed binding paths. UniFFI writes Kotlin under uniffi/<crate>/<name>.kt
# and Swift flat as <name>.swift (renamed to BrairdCore.swift for the SwiftPM target). The
# generated <name>FFI.h + <name>FFI.modulemap are consumed only by build-xcframework.sh for
# the (gitignored) xcframework, so they are not committed and not compared by the guard.
mkdir -p "bindings/kotlin/src/main/kotlin/uniffi/${NAME}"
cp "${GEN}/uniffi/${NAME}/${NAME}.kt" "bindings/kotlin/src/main/kotlin/uniffi/${NAME}/${NAME}.kt"

mkdir -p bindings/swift/Sources/BrairdCore
cp "${GEN}/${NAME}.swift" bindings/swift/Sources/BrairdCore/BrairdCore.swift

echo "✓ regenerated:"
echo "    bindings/kotlin/src/main/kotlin/uniffi/${NAME}/${NAME}.kt"
echo "    bindings/swift/Sources/BrairdCore/BrairdCore.swift"
