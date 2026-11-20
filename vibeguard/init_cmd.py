"""Idempotent repository onboarding (`vibeguard init`)."""

from __future__ import annotations

import errno
import json
import logging
import os
import shutil
import stat
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from vibeguard.agents.local import detect_local_servers
from vibeguard.fix_contract import ProviderError

log = logging.getLogger(__name__)

_GITIGNORE_ENTRIES: tuple[str, ...] = (
    ".vibeguard_cache.json",
    "VIBEGUARD_REPORT.md",
    "VIBEGUARD_DESLOP.md",
    "VIBEGUARD_PREFLIGHT.md",
    "VIBEGUARD_STATES.md",
)

_HOOK_MARKER = "# vibeguard:managed"
_PRE_PUSH_HOOK = f"""#!/usr/bin/env bash
{_HOOK_MARKER}
set -euo pipefail
if ! command -v vibeguard >/dev/null 2>&1; then
  echo "vibeguard: CLI not found on PATH; skipping pre-push check" >&2
  exit 0
fi
vibeguard scan . --mode off --no-report --no-cache --quiet
"""

_AGENT_RULE_BODY = """# VibeGuard

Before finishing a task or opening a PR, run `vibeguard` in the repository root.

- Fix every `CRITICAL` and `HIGH` security finding before shipping.
- Do not suppress findings or weaken checks to make the gate pass.
- When a human corrects a recurring mistake, record it with `vibeguard rule add-pattern` or `vibeguard rule add-boundary`.
"""

_CURSOR_RULE_BODY = (
    "---\n"
    "description: Run VibeGuard security and anti-slop checks before finishing changes\n"
    "alwaysApply: true\n"
    "---\n\n"
    + _AGENT_RULE_BODY
)

_CI_WORKFLOW = """name: VibeGuard

on:
  pull_request:

permissions:
  contents: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install vibeguard
      - run: vibeguard scan . --diff "origin/${{ github.base_ref }}" --mode auto
        env:
          GEMINI_API_KEY: ${{ secrets.GEMINI_API_KEY }}
"""


@dataclass(frozen=True)
class InitAction:
    target: str
    status: str  # created | updated | up_to_date | skipped
    detail: str


@dataclass(frozen=True)
class InitReport:
    root: Path
    actions: list[InitAction] = field(default_factory=list)
    live_key_present: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "root": str(self.root),
            "live_key_present": self.live_key_present,
            "actions": [
                {"target": action.target, "status": action.status, "detail": action.detail}
                for action in self.actions
            ],
        }


def run_init(
    root: Path,
    *,
    install_hook: bool = True,
    antigravity: bool = False,
    cursor: bool = False,
    claude: bool = False,
    codex: bool = False,
    ci: bool = False,
    force: bool = False,
) -> InitReport:
    """Configure a repository for VibeGuard without overwriting user files."""
    resolved = root.expanduser().resolve()
    if not resolved.is_dir():
        raise FileNotFoundError(f"path is not a directory: {resolved}")

    actions: list[InitAction] = []
    actions.append(_ensure_gitignore(resolved))

    if install_hook:
        actions.append(_ensure_pre_push_hook(resolved, force=force))

    if cursor or (resolved / ".cursor").is_dir():
        actions.append(
            _write_managed_file(
                resolved / ".cursor" / "rules" / "vibeguard.mdc",
                _CURSOR_RULE_BODY,
                label=".cursor/rules/vibeguard.mdc",
                force=force,
            )
        )

    if claude or (resolved / ".claude").is_dir() or (resolved / "CLAUDE.md").is_file():
        actions.append(
            _write_managed_file(
                resolved / ".claude" / "rules" / "vibeguard.md",
                _AGENT_RULE_BODY,
                label=".claude/rules/vibeguard.md",
                force=force,
            )
        )
        actions.append(
            _install_bundled_plugin(
                resolved,
                label=".claude/plugins/vibeguard",
                source=_bundled(("integrations", "claude-code", "vibeguard"), ".claude-plugin/plugin.json"),
                detail="installed Claude Code Start skill, fixer agent, and hooks",
                force=force,
            )
        )

    if antigravity or (resolved / ".agents").is_dir():
        actions.append(_install_antigravity_plugin(resolved, force=force))

    if codex or (resolved / ".codex").is_dir():
        actions.append(
            _install_bundled_plugin(
                resolved,
                label=".codex/plugins/vibeguard",
                source=_bundled(("integrations", "codex", "vibeguard"), ".codex-plugin/plugin.json"),
                detail="installed Codex Start skill",
                force=force,
            )
        )

    local_action = _record_local_server(resolved, force=force)
    if local_action is not None:
        actions.append(local_action)

    if ci:
        actions.append(
            _write_managed_file(
                resolved / ".github" / "workflows" / "vibeguard.yml",
                _CI_WORKFLOW,
                label=".github/workflows/vibeguard.yml",
                force=force,
            )
        )

    live_key = bool((os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY") or "").strip())
    return InitReport(root=resolved, actions=actions, live_key_present=live_key)


def _ensure_gitignore(root: Path) -> InitAction:
    path = root / ".gitignore"
    existed = path.is_file()
    existing_text = path.read_text(encoding="utf-8") if existed else ""
    existing_lines = {line.strip() for line in existing_text.splitlines()}
    missing = [entry for entry in _GITIGNORE_ENTRIES if entry not in existing_lines]
    if not missing:
        return InitAction(".gitignore", "up_to_date", "already ignores VibeGuard reports and cache")
    prefix = ""
    if existing_text and not existing_text.endswith("\n"):
        prefix = "\n"
    if existing_text:
        prefix += "\n"
    block = "# VibeGuard\n" + "\n".join(missing) + "\n"
    path.write_text(existing_text + prefix + block, encoding="utf-8")
    status = "updated" if existed else "created"
    return InitAction(".gitignore", status, f"added {len(missing)} VibeGuard ignore entries")


def _git_hooks_dir(root: Path) -> Path | None:
    if not (root / ".git").exists():
        return None
    proc = subprocess.run(
        ["git", "rev-parse", "--git-path", "hooks"],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0 or not proc.stdout.strip():
        return None
    raw = Path(proc.stdout.strip())
    return raw if raw.is_absolute() else (root / raw).resolve()


def _ensure_pre_push_hook(root: Path, *, force: bool) -> InitAction:
    hooks_dir = _git_hooks_dir(root)
    if hooks_dir is None:
        return InitAction(".git/hooks/pre-push", "skipped", "not a git repository")
    hook_path = hooks_dir / "pre-push"
    try:
        if hook_path.is_file():
            current = hook_path.read_text(encoding="utf-8", errors="replace")
            if _HOOK_MARKER in current and not force:
                return InitAction(".git/hooks/pre-push", "up_to_date", "managed pre-push hook already installed")
            if _HOOK_MARKER not in current and not force:
                return InitAction(
                    ".git/hooks/pre-push",
                    "skipped",
                    "existing pre-push hook found (re-run with --force to replace)",
                )
        hooks_dir.mkdir(parents=True, exist_ok=True)
        existed = hook_path.is_file()
        hook_path.write_text(_PRE_PUSH_HOOK, encoding="utf-8")
        hook_path.chmod(hook_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    except OSError as exc:
        if not _write_denied(exc):
            raise
        return InitAction(".git/hooks/pre-push", "skipped", "not permitted to write the pre-push hook")
    return InitAction(
        ".git/hooks/pre-push",
        "updated" if existed else "created",
        "runs Layer 1 scan (--mode off --quiet) before push",
    )


def _write_denied(exc: OSError) -> bool:
    return exc.errno in (errno.EPERM, errno.EACCES)


def _write_managed_file(path: Path, content: str, *, label: str, force: bool) -> InitAction:
    try:
        if path.is_file():
            current = path.read_text(encoding="utf-8", errors="replace")
            if current == content:
                return InitAction(label, "up_to_date", "already configured")
            if not force:
                return InitAction(label, "skipped", "file already exists (re-run with --force to overwrite)")
            path.write_text(content, encoding="utf-8")
            return InitAction(label, "updated", "overwrote with VibeGuard template")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    except OSError as exc:
        if not _write_denied(exc):
            raise
        return InitAction(label, "skipped", f"not permitted to write {label}")
    return InitAction(label, "created", "installed VibeGuard config")


def _antigravity_source() -> Path | None:
    candidates = (
        Path(__file__).resolve().parent / "_bundled" / "antigravity" / "vibeguard",
        Path(__file__).resolve().parents[1] / "integrations" / "antigravity" / "vibeguard",
    )
    for candidate in candidates:
        if (candidate / "plugin.json").is_file():
            return candidate
    return None


def _install_antigravity_plugin(root: Path, *, force: bool) -> InitAction:
    label = ".agents/plugins/vibeguard"
    src = _antigravity_source()
    if src is None:
        return InitAction(label, "skipped", "bundled Antigravity plugin files not found in this install")
    try:
        dest = root / ".agents" / "plugins" / "vibeguard"
        if dest.exists() and not force:
            return InitAction(label, "up_to_date", "plugin already installed (re-run with --force to refresh)")
        if dest.exists():
            shutil.rmtree(dest)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(src, dest)
        _chmod_plugin(dest)
    except OSError as exc:
        if not _write_denied(exc):
            raise
        return InitAction(label, "skipped", f"not permitted to write {label}")
    return InitAction(label, "created", "installed Antigravity Stop + PostToolUse hooks and skills")


def _bundled(parts: tuple[str, ...], marker: str) -> Path | None:
    candidate = Path(__file__).resolve().parents[1].joinpath(*parts)
    if (candidate / marker).is_file():
        return candidate
    return None


def _install_bundled_plugin(
    root: Path,
    *,
    label: str,
    source: Path | None,
    detail: str,
    force: bool,
) -> InitAction:
    if source is None:
        return InitAction(label, "skipped", "bundled plugin files not found in this install")
    try:
        dest = root / label
        if dest.exists() and not force:
            return InitAction(label, "up_to_date", "plugin already installed (re-run with --force to refresh)")
        if dest.exists():
            shutil.rmtree(dest)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(source, dest)
        _chmod_plugin(dest)
    except OSError as exc:
        if not _write_denied(exc):
            raise
        return InitAction(label, "skipped", f"not permitted to write {label}")
    return InitAction(label, "created", detail)


def _chmod_plugin(dest: Path) -> None:
    scripts = dest / "scripts"
    if scripts.is_dir():
        scripts.chmod(0o755)
        for script in scripts.iterdir():
            if script.is_file():
                script.chmod(0o755)
    for script in dest.glob("hooks/*.sh"):
        script.chmod(0o755)


def _record_local_server(root: Path, *, force: bool) -> InitAction | None:
    label = ".vibeguard/config.json"
    try:
        servers = detect_local_servers()
    except ProviderError as exc:
        log.warning("local model detection failed: %s", exc)
        return InitAction(label, "skipped", str(exc))
    if not servers or not servers[0].models:
        return None
    desired = {"url": servers[0].url, "model": servers[0].models[0]}
    path = root / ".vibeguard" / "config.json"
    current: dict[str, object] = {}
    existed = path.is_file()
    if existed:
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            if not force:
                return InitAction(label, "skipped", f"config.json is not valid JSON ({exc})")
            loaded = {}
        if isinstance(loaded, dict):
            current = loaded
        elif not force:
            return InitAction(label, "skipped", "config.json must be an object")
        existing = current.get("local")
        if existing == desired:
            return InitAction(label, "up_to_date", "local server already recorded")
        if existing is not None and not force:
            return InitAction(
                label,
                "skipped",
                "local server already configured (re-run with --force to replace)",
            )
    path.parent.mkdir(parents=True, exist_ok=True)
    current["local"] = desired
    path.write_text(json.dumps(current, indent=2) + "\n", encoding="utf-8")
    return InitAction(
        label,
        "updated" if existed else "created",
        f"recorded {desired['model']} at {desired['url']}",
    )


def render_init_summary(report: InitReport) -> str:
    lines = [f"VibeGuard initialized in {report.root}:"]
    for action in report.actions:
        lines.append(f"  [{action.status}] {action.target}: {action.detail}")
    if report.live_key_present:
        lines.append("Layer 2: live gemini-decision-1 enabled (API key detected).")
    else:
        lines.append(
            "Layer 2: offline heuristic mode ($0, no key needed). "
            "Export GEMINI_API_KEY anytime for live gemini-decision-1."
        )
    lines.append("Next: run `vibeguard` to scan this repository.")
    return "\n".join(lines)
