# VibeCleaner for Antigravity

VibeCleaner checks AI-generated code for security holes and slop before an Antigravity agent finishes a turn.

The Stop hook runs `vibecleaner scan . --diff "$VIBECLEANER_BASE" --quiet` (`VIBECLEANER_BASE` defaults to `main`). Layer 1 runs on the changed files and Layer 2 on the changed functions (`--mode auto`: live `gemini-decision-1` when `GEMINI_API_KEY` or `GOOGLE_API_KEY` is set, otherwise the offline heuristic). If the base ref is missing, or the workspace is not a git repository, the hook scans the full tree. A clean scan returns `{}` and injects nothing into the conversation. Findings return `{"decision":"continue","reason":"..."}` with exit 0, which keeps the agent working until the findings are fixed. Scanner or configuration errors (`exit 2`) or a missing `vibecleaner` CLI fail closed on `Stop` (returning `{"decision":"continue","reason":"..."}`).

After `write_to_file`, `replace_file_content`, or `multi_replace_file_content`, a PostToolUse hook runs Layer 1 only (`--mode off`). PostToolUse cannot block a tool; it returns `{}` and writes any findings or errors to the hook log. The Stop hook is the gate.

The hook adds `--no-report` and `--no-cache` so a turn does not write `VIBECLEANER_REPORT.md` or `.vibecleaner_cache.json`.

## Install

The `vibecleaner` CLI must be on `PATH` for the process that runs hooks:

```bash
pip install vibecleaner
```

Copy this directory into the Antigravity plugin folder, or use the installer at the repository root:

```bash
# current user
scripts/install_antigravity_plugin.sh

# one workspace
scripts/install_antigravity_plugin.sh --workspace /path/to/repo
```

That copies the plugin to `~/.gemini/config/plugins/vibecleaner/` or `<DIR>/.agents/plugins/vibecleaner/` and marks `scripts/` executable (`0755`).

You can also copy the directory yourself:

```bash
mkdir -p ~/.gemini/config/plugins
cp -R integrations/antigravity/vibecleaner ~/.gemini/config/plugins/vibecleaner
chmod 0755 ~/.gemini/config/plugins/vibecleaner/scripts/vibecleaner-hook.sh
```

Restart Antigravity, or validate the folder:

```bash
agy plugin validate --strict ~/.gemini/config/plugins/vibecleaner
```

Optional: export `GEMINI_API_KEY` (or `GOOGLE_API_KEY`) for live Layer 2, and `VIBECLEANER_BASE` when the diff base is not `main`.

## What you get

- `hooks.json`: Stop and PostToolUse hooks
- `rules/vibecleaner.md`: always-on rule to fix findings, never suppress checks, turn corrections into project rules, keep docs/comments free of AI slop, and stop on review tier 4 for a security review
- `skills/audit-code/SKILL.md`: `/audit-code` walks `vibecleaner scan --diff main`, the report, and `--fix`, and stops on review tier 3 or 4 so a person reads the listed files
- `skills/deslop/SKILL.md`: `/deslop` runs `vibecleaner deslop` and assigns each cleanup lane to its own agent
- `skills/preflight/SKILL.md`: `/preflight` runs the 42-check launch review
- `skills/correct/SKILL.md`: `/correct` turns a human correction into `.vibecleaner/rules.json`
