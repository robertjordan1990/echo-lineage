#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PACK_DIR="$ROOT_DIR/public_kit/PUBLIC_PACK"

# 1) fingerprint must match ledger
FP_WANT="$(cat "$PACK_DIR/FINGERPRINT.txt" | tr -d '\r\n' )"
FP_GOT="$(sha256sum "$PACK_DIR/LEDGER__sha256.txt" | awk '{print $1}')"

if [[ "$FP_WANT" != "$FP_GOT" ]]; then
  echo "FAIL: FINGERPRINT mismatch"
  echo "  want: $FP_WANT"
  echo "  got : $FP_GOT"
  exit 2
fi

echo "OK: fingerprint matches ledger"

# 2) ledger entries and the exact public file set must verify.
# FINGERPRINT is intentionally excluded because it hashes the ledger itself.
python3 "$ROOT_DIR/tools/tools/echo_ledger.py" verify \
  "$PACK_DIR/LEDGER__sha256.txt" \
  --root "$PACK_DIR" \
  --strict \
  --exclude FINGERPRINT.txt

# 3) public pack must not contain risky binary types
BAD=$(find "$PACK_DIR" -type f \( \
  -iname "*.pdf" -o -iname "*.zip" -o -iname "*.7z" -o -iname "*.tar" -o -iname "*.gz" \
  -o -iname "*.enc" -o -iname "*.key" -o -iname "*.pem" -o -iname "*.p12" -o -iname "*.pfx" \
  -o -iname "*.asc" -o -iname "*.gpg" \
\) | sed -n '1,50p' || true)

if [[ -n "$BAD" ]]; then
  echo "FAIL: forbidden file type(s) found in PUBLIC_PACK (showing up to 50):"
  echo "$BAD"
  exit 3
fi

echo "OK: no forbidden binary types in PUBLIC_PACK"
