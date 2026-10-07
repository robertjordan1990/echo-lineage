#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PACK_DIR="$ROOT_DIR/public_kit/PUBLIC_PACK"

# 1) regenerate ledger excluding FINGERPRINT to avoid circular dependency
python3 "$ROOT_DIR/tools/tools/echo_ledger.py" make "$PACK_DIR" \
  --out "$PACK_DIR/LEDGER__sha256.txt" \
  --exclude FINGERPRINT.txt

# 2) regenerate fingerprint
FP="$(sha256sum "$PACK_DIR/LEDGER__sha256.txt" | awk '{print $1}')"
printf "%s\n" "$FP" > "$PACK_DIR/FINGERPRINT.txt"

echo "Updated PUBLIC_PACK ledger + fingerprint"

echo "FINGERPRINT: $FP"
