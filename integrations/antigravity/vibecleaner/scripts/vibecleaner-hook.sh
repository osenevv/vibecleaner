#!/usr/bin/env bash
# Antigravity lifecycle hook for VibeCleaner.
#
# Stop (end of turn): run `vibecleaner scan . --diff <base> --quiet`.
#   base is $VIBECLEANER_BASE, default main. If that ref is missing, or this
#   directory is not a git work tree, scan the whole tree.
#   Blocking uses --fail-on ${VIBECLEANER_FAIL_ON:-critical}.
# PostToolUse (file edits): the same scan with `--mode off` (Layer 1 only).
#
# Blocking follows the Antigravity hook contract:
#   Command hooks must exit 0 and write a JSON object to stdout.
#   Stop blocks only when vibecleaner exits 1, with
#   {"decision":"continue","reason":"..."} (the reason includes the findings).
#   Exit 0 allows the stop with {}, even when lower-severity findings printed.
#   Exit 2 (scanner/API error) or missing CLI fails closed on Stop and open on PostToolUse.
#   PostToolUse cannot block; it returns {} and audits on stderr.

set -euo pipefail

py() {
  if command -v python3 >/dev/null 2>&1; then
    command python3 "$@"
  else
    command python "$@"
  fi
}

event="${1:-stop}"
case "$event" in
  stop | post-tool) ;;
  *)
    echo "usage: vibecleaner-hook.sh [stop|post-tool]" >&2
    printf '%s\n' '{}'
    exit 0
    ;;
esac

payload_file="$(mktemp)"
err_file="$(mktemp)"
trap 'rm -f "$payload_file" "$err_file"' EXIT
cat >"$payload_file" || true

workspace="$(
  py - "$payload_file" <<'PY' || true
import json
import sys
from pathlib import Path

try:
    raw = Path(sys.argv[1]).read_text(encoding="utf-8")
    data = json.loads(raw) if raw.strip() else {}
except (OSError, UnicodeError, json.JSONDecodeError):
    data = {}
if not isinstance(data, dict):
    data = {}
paths = data.get("workspacePaths") or []
if not isinstance(paths, list):
    paths = []
paths = [item for item in paths if isinstance(item, str) and item.strip()]
target = ""
tool = data.get("toolCall")
if isinstance(tool, dict):
    args = tool.get("args")
    if isinstance(args, dict):
        for key in ("TargetFile", "Cwd", "AbsolutePath", "DirectoryPath"):
            value = args.get(key)
            if isinstance(value, str) and value.strip():
                target = value.strip()
                break
chosen = ""
if target:
    norm = target.rstrip("/") or target
    for path in paths:
        root = path.rstrip("/") or path
        if norm == root or norm.startswith(root + "/"):
            chosen = path
            break
    if not chosen and not paths:
        chosen = target
if not chosen and paths:
    chosen = paths[0]
sys.stdout.write(chosen)
PY
)"

if [ -z "$workspace" ]; then
  workspace="$(pwd)"
elif [ -f "$workspace" ]; then
  workspace="$(dirname "$workspace")"
fi

if [ ! -d "$workspace" ]; then
  echo "VibeCleaner hook: workspace does not exist: $workspace" >&2
  printf '%s\n' '{}'
  exit 2
fi

cd "$workspace"

emit_continue_reason() {
  REASON="$1" py -c 'import json, os, sys
text = os.environ.get("REASON", "")
if len(text) > 8000:
    text = text[:8000] + "\n…[truncated]"
json.dump({"decision": "continue", "reason": text}, sys.stdout)
sys.stdout.write("\n")'
}

if ! command -v vibecleaner >/dev/null 2>&1; then
  cat >&2 <<'EOF'
VibeCleaner hook: `vibecleaner` is not on PATH.
Install the CLI and restart the agent so this hook can see it:
  pip install vibecleaner
From a checkout of this repository:
  pip install -e .
EOF
  if [ "$event" = "post-tool" ]; then
    printf '%s\n' '{}'
  else
    printf '%s\n' '{"decision": "continue", "reason": "VibeCleaner blocked completion: vibecleaner CLI is not on PATH. Install it (pip install -e .) before completing the task."}'
  fi
  exit 0
fi

base="${VIBECLEANER_BASE:-main}"
use_diff=0
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  if git rev-parse --verify --quiet "${base}^{commit}" >/dev/null 2>&1; then
    use_diff=1
  fi
fi

fail_on="${VIBECLEANER_FAIL_ON:-critical}"
cmd=(vibecleaner scan . --quiet --no-report --no-cache --fail-on "$fail_on")
if [ "$event" = "post-tool" ]; then
  cmd+=(--mode off)
fi
if [ "$use_diff" -eq 1 ]; then
  cmd+=(--diff "$base")
fi

set +e
# Rich wraps at 80 columns when stdout is a pipe unless both COLUMNS and LINES
# are set. Keep each quiet finding on one line.
output="$(COLUMNS=1000 LINES=40 NO_COLOR=1 "${cmd[@]}" 2>"$err_file")"
code=$?
set -e

body="$(printf '%s' "$output" | tr -d '\r')"
body="${body#"${body%%[![:space:]]*}"}"
body="${body%"${body##*[![:space:]]}"}"

if [ "$code" -eq 2 ] || [ "$code" -gt 2 ]; then
  err_text="$(cat "$err_file" 2>/dev/null || true)"
  detail="${body:-${err_text:-unknown error}}"
  if [ -n "$body" ] && [ -n "$err_text" ] && [ "$body" != "$err_text" ]; then
    detail="${body}"$'\n'"${err_text}"
  fi
  echo "VibeCleaner scan error (exit ${code}): ${detail}" >&2
  if [ "$event" = "post-tool" ]; then
    printf '%s\n' '{}'
    exit 0
  fi
  reason="VibeCleaner blocked completion: scan failed with exit ${code}. Fix the scanner or configuration error before completing the task.

${detail}"
  emit_continue_reason "$reason"
  exit 0
fi

if [ "$code" -ne 1 ]; then
  printf '%s\n' '{}'
  exit 0
fi

reason="VibeCleaner blocked completion. Fix these findings in code. Do not suppress a rule, skip the hook, or mark the task done while they remain.

${body:-VibeCleaner exited ${code} with no report.}"

if [ "$event" = "post-tool" ]; then
  # PostToolUse receives the tool call, not a gate. Return {} and log.
  printf '%s\n' "$reason" >&2
  printf '%s\n' '{}'
  exit 0
fi

emit_continue_reason "$reason"
exit 0
