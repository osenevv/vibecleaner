#!/bin/sh
set -eu

page=$1
size=$2
shift 2
if [ "$page" -lt 1 ] || [ "$size" -lt 1 ]; then
  echo "page and size start at 1" >&2
  exit 2
fi
start=$(( (page - 1) * size ))
end=$(( start + size - 1 ))
index=0
for item in "$@"; do
  if [ "$index" -ge "$start" ] && [ "$index" -lt "$end" ]; then
    printf '%s\n' "$item"
  fi
  index=$(( index + 1 ))
done
