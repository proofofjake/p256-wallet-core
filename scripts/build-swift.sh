#!/usr/bin/env bash
# Builds bindings/swift from source: a static-library XCFramework (iOS device, iOS Simulator, macOS) plus the
# UniFFI-generated Swift file. Apps depend on bindings/swift as a local Swift package. Apple Silicon Macs only.
set -euo pipefail
cd "$(dirname "$0")/.."

export IPHONEOS_DEPLOYMENT_TARGET=17.0
export MACOSX_DEPLOYMENT_TARGET=14.0
TARGETS=(aarch64-apple-ios aarch64-apple-ios-sim aarch64-apple-darwin)
for target in "${TARGETS[@]}"; do
  cargo build --release --locked --lib --features uniffi --target "$target"
done

OUT=target/uniffi-swift
rm -rf "$OUT"
cargo run --release --locked --features uniffi-cli --bin uniffi-bindgen -- generate \
  --library target/aarch64-apple-darwin/release/libp256_wallet_core.dylib \
  --language swift --out-dir "$OUT"

# Headers live in a subdirectory named after the module so they can't collide with other XCFrameworks' headers.
HEADERS="$OUT/headers"
mkdir -p "$HEADERS/P256WalletCoreFFI"
cp "$OUT/P256WalletCoreFFI.h" "$HEADERS/P256WalletCoreFFI/"
cp "$OUT/P256WalletCoreFFI.modulemap" "$HEADERS/P256WalletCoreFFI/module.modulemap"

FRAMEWORK=bindings/swift/P256WalletCoreFFI.xcframework
rm -rf "$FRAMEWORK"
args=()
for target in "${TARGETS[@]}"; do
  args+=(-library "target/$target/release/libp256_wallet_core.a" -headers "$HEADERS")
done
xcodebuild -create-xcframework "${args[@]}" -output "$FRAMEWORK" >/dev/null
cp "$OUT/P256WalletCore.swift" bindings/swift/Sources/P256WalletCore/
echo "Built $FRAMEWORK and bindings/swift/Sources/P256WalletCore/P256WalletCore.swift (core $(cargo pkgid | sed 's/.*[#@]//'))"
