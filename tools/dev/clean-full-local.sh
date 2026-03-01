#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

"$ROOT_DIR/tools/dev/clean-heavy-artifacts.sh"

# Full local cleanup for reproducible local caches/deps.
EXTRA=(
  "node_modules"
  "*.tsbuildinfo"
)

for pattern in "${EXTRA[@]}"; do
  shopt -s nullglob
  matches=("$ROOT_DIR"/$pattern)
  shopt -u nullglob
  if [ "${#matches[@]}" -eq 0 ]; then
    printf 'skip %s (not present)\n' "$pattern"
    continue
  fi
  for m in "${matches[@]}"; do
    rel="${m#"$ROOT_DIR"/}"
    rm -rf "$m"
    printf 'removed %s\n' "$rel"
  done
done
