#!/usr/bin/env bash
set -euo pipefail

mode="${1:-build}"
if [[ "$mode" != build && "$mode" != --check ]]; then
  echo "usage: $0 [--check]" >&2
  exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
toolchain="${SHAR_WASM_RUST_TOOLCHAIN:-1.94.0}"
rustc_path="$(rustup which --toolchain "$toolchain" rustc)"
cargo_path="$(rustup which --toolchain "$toolchain" cargo)"
artifact="$repo_root/target/wasm32-unknown-unknown/release/shar_widget_wasm.wasm"
published="$repo_root/packages/widget/wasm/shar_timelock.wasm"

env RUSTC="$rustc_path" "$cargo_path" build \
  --manifest-path "$repo_root/Cargo.toml" \
  --package shar-widget-wasm \
  --release \
  --target wasm32-unknown-unknown \
  --locked

if [[ "$mode" == --check ]]; then
  cmp "$artifact" "$published" || {
    echo "widget WASM artifact differs; run scripts/build-widget-wasm.sh" >&2
    exit 1
  }
  echo "widget WASM artifact is reproducible with Rust $toolchain"
else
  install -D -m 0644 "$artifact" "$published"
  sha256sum "$published"
fi
