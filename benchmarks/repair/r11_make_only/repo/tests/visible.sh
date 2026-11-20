#!/bin/sh
set -eu
cd "$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
fail=0

out=$(sh ./page.sh 1 2)
if [ -n "$out" ]; then
  echo "empty list should be empty" >&2
  fail=1
fi

out=$(sh ./page.sh 1 2 bolt nut washer screw)
expected=$(printf 'bolt\nnut')
if [ "$out" != "$expected" ]; then
  echo "first page mismatch" >&2
  fail=1
fi

if sh ./page.sh 0 2 bolt >/dev/null 2>&1; then
  echo "page 0 should fail" >&2
  fail=1
fi

exit "$fail"
