# VibeGuard for Antigravity

VibeGuard checks AI-generated code for security holes and slop before an Antigravity agent finishes a turn.

The Stop hook runs `vibeguard scan . --diff "$VIBEGUARD_BASE" --quiet` (`VIBEGUARD_BASE` defaults to `main`). That is the deterministic gate plus Layer 2 (`--mode auto`: live `gemini-decision-1` when `GEMINI_API_KEY` or `GOOGLE_API_KEY` is set, otherwise the offline heuristic). If the base ref is missing, or the workspace is not a git repository, the hook scans the full tree. A clean scan returns `{}` and injects nothing into the conversation. Findings return `{"decision":"continue","reason":"..."}` with exit 0, which keeps the agent working until the findings are fixed.

After `write_to_file`, `replace_file_content`, or `multi_replace_file_content`, a PostToolUse hook runs Layer 1 only (`--mode off`). PostToolUse cannot block a tool; it returns `{}` and writes any findings to the hook log. The Stop hook is the gate.

The hook adds `--no-report` and `--no-cache` so a turn does not write `VIBEGUARD_REPORT.md` or `.vibeguard_cache.json`.

## Install

The `vibeguard` CLI must be on `PATH` for the process that runs hooks:

```bash
pip install vibeguard
```

Copy this directory into the Antigravity plugin folder, or use the installer at the repository root:

```bash
# current user
scripts/install_antigravity_plugin.sh

# one workspace
scripts/install_antigravity_plugin.sh --workspace /path/to/repo
```

That copies the plugin to `~/.gemini/config/plugins/vibeguard/` or `<DIR>/.agents/plugins/vibeguard/` and marks `scripts/` executable (`0755`).

You can also copy the directory yourself:

```bash
mkdir -p ~/.gemini/config/plugins
cp -R integrations/antigravity/vibeguard ~/.gemini/config/plugins/vibeguard
chmod 0755 ~/.gemini/config/plugins/vibeguard/scripts/vibeguard-hook.sh
```

Restart Antigravity, or validate the folder:

```bash
agy plugin validate --strict ~/.gemini/config/plugins/vibeguard
```

Optional: export `GEMINI_API_KEY` (or `GOOGLE_API_KEY`) for live Layer 2, and `VIBEGUARD_BASE` when the diff base is not `main`.

## What you get

- `hooks.json` — Stop and PostToolUse hooks
- `rules/vibeguard.md` — always-on rule: fix findings, do not suppress them
- `skills/audit-code/SKILL.md` — `/audit-code` walks `vibeguard scan --diff main`, the report, and `--fix`
