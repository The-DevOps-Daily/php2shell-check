#!/bin/sh
# Save a timestamped run of compare-hub-index.py to results/.
set -eu
cd "$(dirname "$0")/.."
ts=$(date -u +%Y%m%dT%H%M%SZ)
out=results/method-check-$ts.txt
{
  echo "# $(date -u +%Y-%m-%dT%H:%M:%SZ) scripts/compare-hub-index.py $*"
  python3 scripts/compare-hub-index.py "$@"
} > "$out" 2>&1
cat "$out"
