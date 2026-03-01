#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

find_free_port() {
  local candidate
  for candidate in 1420 1430 1431 1432 1433 1434 1435 1436 1437 1438 1439 1440; do
    if ! lsof -nP -iTCP:"$candidate" -sTCP:LISTEN >/dev/null 2>&1; then
      printf '%s' "$candidate"
      return 0
    fi
  done
  return 1
}

LEAN_TMP_DIR="$(mktemp -d -t aigc-lean-dev-XXXXXX)"
LEAN_PORT="${LEAN_DEV_PORT:-}"
if [ -z "$LEAN_PORT" ]; then
  LEAN_PORT="$(find_free_port || true)"
fi
if [ -z "$LEAN_PORT" ]; then
  echo "Could not find a free local port in 1420-1440."
  echo "Set LEAN_DEV_PORT to an available port and retry."
  exit 1
fi

LEAN_CONFIG_FILE="$LEAN_TMP_DIR/tauri.lean.conf.json"
cat > "$LEAN_CONFIG_FILE" <<JSON
{
  "build": {
    "devUrl": "http://127.0.0.1:${LEAN_PORT}",
    "beforeDevCommand": "VITE_HOST=127.0.0.1 VITE_PORT=${LEAN_PORT} VITE_CACHE_DIR=${LEAN_TMP_DIR}/vite-cache pnpm dev:ui"
  }
}
JSON

export CARGO_TARGET_DIR="$LEAN_TMP_DIR/cargo-target"

cleanup() {
  set +e
  "$ROOT_DIR/tools/dev/clean-heavy-artifacts.sh" >/dev/null 2>&1 || true
  rm -rf "$LEAN_TMP_DIR"
}
trap cleanup EXIT INT TERM

cd "$ROOT_DIR"
echo "Lean dev using temp dir: $LEAN_TMP_DIR"
echo "Lean dev frontend URL: http://127.0.0.1:${LEAN_PORT}"

pnpm tauri dev -c "$LEAN_CONFIG_FILE" "$@"
