#!/usr/bin/env bash
# Copy the VibeCleaner Antigravity plugin into the user profile or a workspace.
# Usage: scripts/install_antigravity_plugin.sh [--workspace DIR]

set -euo pipefail

workspace=""
while [ $# -gt 0 ]; do
  case "$1" in
    --workspace)
      if [ $# -lt 2 ]; then
        echo "missing DIR for --workspace" >&2
        exit 2
      fi
      workspace="$2"
      shift 2
      ;;
    --workspace=*)
      workspace="${1#--workspace=}"
      if [ -z "$workspace" ]; then
        echo "missing DIR for --workspace" >&2
        exit 2
      fi
      shift
      ;;
    -h | --help)
      echo "usage: scripts/install_antigravity_plugin.sh [--workspace DIR]"
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"
src="${repo_root}/integrations/antigravity/vibecleaner"

if [ ! -f "${src}/plugin.json" ]; then
  echo "plugin source not found: ${src}" >&2
  exit 1
fi

if [ -n "$workspace" ]; then
  dest="${workspace}/.agents/plugins/vibecleaner"
else
  dest="${HOME}/.gemini/config/plugins/vibecleaner"
fi

case "$dest" in
  */vibecleaner) ;;
  *)
    echo "refusing to replace unexpected path: ${dest}" >&2
    exit 1
    ;;
esac

mkdir -p "$(dirname "$dest")"
rm -rf "$dest"
mkdir -p "$dest"
cp -R "${src}/." "$dest/"
chmod 0755 "${dest}/scripts"
find "${dest}/scripts" -type f -exec chmod 0755 {} +

cat <<EOF
Installed VibeCleaner to ${dest}

Next steps:
  1. Install the CLI so hooks can find it: pip install vibecleaner
     (or, from this repo: pip install -e .)
  2. Confirm \`vibecleaner\` is on PATH for the Antigravity process.
  3. Optional: export GEMINI_API_KEY or GOOGLE_API_KEY for live Layer 2.
     Without a key, --mode auto uses the offline heuristic.
  4. Optional: export VIBECLEANER_BASE if the diff base is not main.
  5. Restart Antigravity, or run:
     agy plugin validate --strict "${dest}"
EOF
