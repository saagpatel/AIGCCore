#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# Reproducible heavy build outputs only.
CANDIDATES=(
  "dist"
  "target"
  "src-tauri/target"
  ".vite"
  "node_modules/.vite"
)

removed_any=0
for rel in "${CANDIDATES[@]}"; do
  abs="$ROOT_DIR/$rel"
  if [ -e "$abs" ]; then
    rm -rf "$abs"
    printf 'removed %s\n' "$rel"
    removed_any=1
  else
    printf 'skip %s (not present)\n' "$rel"
  fi
done

if [ "$removed_any" -eq 0 ]; then
  echo "No heavy build artifacts were present."
fi
