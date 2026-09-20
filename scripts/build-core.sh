#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
clang --target=wasm32 -O3 -nostdlib \
  -Wl,--no-entry \
  -Wl,--export=jend_core_version \
  -Wl,--export=jend_guard_min_delay \
  -Wl,--export=jend_guard_score \
  -Wl,--export=jend_guard_allow \
  -Wl,--strip-all \
  "$ROOT/native/jend_core.c" \
  -o "$ROOT/worker/core/jend-core.wasm"
echo "Built worker/core/jend-core.wasm"
