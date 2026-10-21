#!/bin/sh
# Run the host check and keep the output, with the time and the exit code.
# Usage: scripts/record-example.sh <name> "<one line describing the host>"
set -u
cd "$(dirname "$0")/.."
name=$1
host=$2
out=examples/$name.txt
{
  echo "# $(date -u +%Y-%m-%dT%H:%M:%SZ) $host"
  echo "\$ python3 php2shell_check.py"
  python3 php2shell_check.py
  rc=$?
  echo "\$ echo \$?"
  echo $rc
} > "$out" 2>&1
python3 php2shell_check.py --json > "examples/$name.json"
cat "$out"
