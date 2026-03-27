#!/usr/bin/env bash
set -euo pipefail

SYMBOLS="${1:-/tmp/talos-kernel/symbols.txt}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

printf "\n%-30s %-10s %-10s %s\n" "FUNCTION" "SELECTOR" "STATUS" "DETAIL"
printf "%-30s %-10s %-10s %s\n" "--------" "--------" "------" "------"

fail=0
while IFS=' ' read -r func sel; do
  [[ "$func" =~ ^#|^$ ]] && continue

  # Exact match: symbol name followed by end-of-line or whitespace, NOT a dot
  exact=$(grep -cP "\b${func}(?!\.)\b" "$SYMBOLS" || true)

  # Suffixed variant: symbol.isra.N, symbol.constprop.N, symbol.part.N
  suffixed=$(grep -oP "\b${func}\.(isra|constprop|part)\.[0-9]+\b" "$SYMBOLS" | head -1 || true)

  if [ "$exact" -gt 0 ]; then
    printf "%-30s %-10s %-10s %s\n" "$func" "$sel" "OK" ""
  elif [ -n "$suffixed" ]; then
    printf "%-30s %-10s %-10s %s\n" "$func" "$sel" "MISMATCH" "$suffixed"
    fail=1
  else
    printf "%-30s %-10s %-10s %s\n" "$func" "$sel" "MISSING" ""
    fail=1
  fi
done < "$SCRIPT_DIR/expected-probes.txt"

echo ""
exit $fail
