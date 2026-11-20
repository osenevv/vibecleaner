#!/usr/bin/env bash
# Antigravity lifecycle hook for VibeGuard.
#
# Stop (end of turn): run `vibeguard scan . --diff <base> --quiet`.
#   base is $VIBEGUARD_BASE, default main. If that ref is missing, or this
#   directory is not a git work tree, scan the whole tree.
# PostToolUse (file edits): the same scan with `--mode off` (Layer 1 only).
#
# Blocking follows the Antigravity hook contract:
#   Command hooks must exit 0 and write a JSON object to stdout.
#   Stop blocks with {"decision":"continue","reason":"..."} and allows the
#   stop with {}. A non-zero exit is logged and ignored (fail open), so a
#   finding must not be signaled with exit 1.
#   PostToolUse cannot block; it returns {} and audits on stderr.
# A clean scan prints nothing into the agent context (stdout is {} only).

set -euo pipefail

event="${1:-stop}"
case "$event" in
  stop | post-tool) ;;
  *)
    echo "usage: vibeguard-hook.sh [stop|post-tool]" >&2
    printf '%s\n' '{}'
    exit 0
    ;;
esac

payload_file="$(mktemp)"
err_file="$(mktemp)"
trap 'rm -f "$payload_file" "$err_file"' EXIT
cat >"$payload_file" || true

workspace="$(
  python3 - "$payload_file" <<'PY' || true
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
  echo "VibeGuard hook: workspace does not exist: $workspace" >&2
  printf '%s\n' '{}'
  exit 2
fi

cd "$workspace"

if ! command -v vibeguard >/dev/null 2>&1; then
  cat >&2 <<'EOF'
VibeGuard hook: `vibeguard` is not on PATH.
Install the CLI and restart the agent so this hook can see it:
  pip install vibeguard
From a checkout of this repository:
  pip install -e .
EOF
  printf '%s\n' '{}'
  exit 0
fi

base="${VIBEGUARD_BASE:-main}"
use_diff=0
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  if git rev-parse --verify --quiet "${base}^{commit}" >/dev/null 2>&1; then
    use_diff=1
  fi
fi

cmd=(vibeguard scan . --quiet --no-report --no-cache)
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

# Quiet mode prints exactly "VIBEGUARD: PASS" when the tree is clean, even if
# every finding is below the CLI's default --fail-on high (exit 0). Any other
# report is a finding the agent still has to fix.
body="$(printf '%s' "$output" | tr -d '\r')"
body="${body#"${body%%[![:space:]]*}"}"
body="${body%"${body##*[![:space:]]}"}"
clean=0
if [ "$code" -eq 0 ] && { [ -z "$body" ] || [ "$body" = "VIBEGUARD: PASS" ]; }; then
  clean=1
fi

if [ "$code" -eq 2 ] || [ "$code" -gt 2 ]; then
  err_text="$(cat "$err_file" 2>/dev/null || true)"
  echo "VibeGuard scan error (exit ${code}): ${err_text:-unknown error}" >&2
  printf '%s\n' '{}'
  exit 2
fi

if [ "$clean" -eq 1 ]; then
  printf '%s\n' '{}'
  exit 0
fi

reason="VibeGuard blocked completion. Fix these findings in code. Do not suppress a rule, skip the hook, or mark the task done while they remain.

${body:-VibeGuard exited ${code} with no report.}"

if [ "$event" = "post-tool" ]; then
  # PostToolUse receives the tool call, not a gate. Return {} and log.
  printf '%s\n' "$reason" >&2
  printf '%s\n' '{}'
  exit 0
fi

REASON="$reason" python3 -c 'import json, os, sys
text = os.environ.get("REASON", "")
if len(text) > 8000:
    text = text[:8000] + "\n…[truncated]"
json.dump({"decision": "continue", "reason": text}, sys.stdout)
sys.stdout.write("\n")'
exit 0
