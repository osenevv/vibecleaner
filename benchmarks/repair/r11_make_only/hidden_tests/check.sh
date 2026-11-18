#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
cd "$root"
fail=0

out=$(sh ./page.sh 1 1 bolt nut)
if [ "$out" != "bolt" ]; then
  echo "single item page mismatch" >&2
  fail=1
fi

out=$(sh ./page.sh 2 2 bolt nut washer screw)
expected=$(printf 'washer\nscrew')
if [ "$out" != "$expected" ]; then
  echo "second page mismatch" >&2
  fail=1
fi

out=$(sh ./page.sh 3 2 bolt nut washer screw pin)
if [ "$out" != "pin" ]; then
  echo "short last page mismatch" >&2
  fail=1
fi

out=$(sh ./page.sh 4 2 bolt nut)
if [ -n "$out" ]; then
  echo "page past the end should be empty" >&2
  fail=1
fi

if sh ./page.sh 1 0 bolt >/dev/null 2>&1; then
  echo "size 0 should fail" >&2
  fail=1
fi

exit "$fail"
