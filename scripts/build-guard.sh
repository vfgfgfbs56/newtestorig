#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$ROOT/public/guard"
clang --target=wasm32 -O3 -nostdlib \
  -Wl,--no-entry \
  -Wl,--export=solve \
  -Wl,--strip-all \
  -o "$ROOT/public/guard/jend-guard-v1.wasm" \
  "$ROOT/native/guard.cpp"
echo "Built public/guard/jend-guard-v1.wasm"
