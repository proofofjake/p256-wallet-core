#!/usr/bin/env bash
# Builds bindings/ts/pkg from source: the WebAssembly module and its wasm-bindgen JS glue. Apps import
# bindings/ts/index.ts, which adds types. Needs wasm-bindgen-cli at the exact version in Cargo.lock:
#   cargo install wasm-bindgen-cli --version <version> --locked
set -euo pipefail
cd "$(dirname "$0")/.."

want=$(grep -A1 '^name = "wasm-bindgen"$' Cargo.lock | sed -n 's/^version = "\(.*\)"/\1/p')
have=$(wasm-bindgen --version 2>/dev/null | awk '{print $2}' || true)
if [[ "$have" != "$want" ]]; then
  echo "wasm-bindgen-cli $want is required (found ${have:-none}): cargo install wasm-bindgen-cli --version $want --locked" >&2
  exit 1
fi

cargo build --release --locked --lib --features wasm --target wasm32-unknown-unknown
rm -rf bindings/ts/pkg
wasm-bindgen --target web --out-dir bindings/ts/pkg target/wasm32-unknown-unknown/release/p256_wallet_core.wasm
echo "Built bindings/ts/pkg ($(wc -c < bindings/ts/pkg/p256_wallet_core_bg.wasm | tr -d ' ') byte wasm, core $(cargo pkgid | sed 's/.*[#@]//'))"
