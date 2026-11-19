"""End-to-end tests for `vibecleaner init` and bare `vibecleaner` default invocation."""

from __future__ import annotations

import errno
import json
import os
import stat
from pathlib import Path

import pytest

from gitutil import hook_file, init_git
from vibecleaner.cli import main


def test_init_creates_gitignore_and_pre_push_hook_idempotently(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    init_git(tmp_path)
    (tmp_path / ".gitignore").write_text("node_modules/\n", encoding="utf-8")
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)

    assert main(["init", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "VibeCleaner initialized" in out
    assert "offline heuristic mode" in out

    gitignore = (tmp_path / ".gitignore").read_text(encoding="utf-8")
    assert "node_modules/" in gitignore
    for entry in (
        ".vibecleaner_cache.json",
        "VIBECLEANER_REPORT.md",
        "VIBECLEANER_DESLOP.md",
        "VIBECLEANER_PREFLIGHT.md",
        "VIBECLEANER_STATES.md",
    ):
        assert entry in gitignore

    hook = hook_file(tmp_path)
    assert hook.is_file()
    assert bool(hook.stat().st_mode & stat.S_IXUSR)
    assert "vibecleaner scan . --mode off" in hook.read_text(encoding="utf-8")

    # Second run is idempotent: no duplicate lines, statuses are up_to_date.
    assert main(["init", str(tmp_path), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["live_key_present"] is False
    statuses = {item["target"]: item["status"] for item in payload["actions"]}
    assert statuses[".gitignore"] == "up_to_date"
    assert statuses[".git/hooks/pre-push"] == "up_to_date"
    assert (tmp_path / ".gitignore").read_text(encoding="utf-8") == gitignore


def test_init_preserves_existing_user_hook_unless_forced(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    init_git(tmp_path)
    hook = hook_file(tmp_path)
    hook.parent.mkdir(parents=True, exist_ok=True)
    hook.write_text("#!/usr/bin/env bash\necho custom\n", encoding="utf-8")

    assert main(["init", str(tmp_path), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    statuses = {item["target"]: item["status"] for item in payload["actions"]}
    assert statuses[".git/hooks/pre-push"] == "skipped"
    assert "echo custom" in hook.read_text(encoding="utf-8")

    assert main(["init", str(tmp_path), "--force", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    statuses = {item["target"]: item["status"] for item in payload["actions"]}
    assert statuses[".git/hooks/pre-push"] == "updated"
    assert "vibecleaner scan . --mode off" in hook.read_text(encoding="utf-8")


def test_init_autodetects_editor_configs_and_ci_flag(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    cursor_present = _try_editor_dir(tmp_path / ".cursor")
    (tmp_path / "CLAUDE.md").write_text("# Notes\n", encoding="utf-8")
    (tmp_path / ".agents").mkdir()
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")

    assert main(["init", str(tmp_path), "--ci", "--no-hook", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["live_key_present"] is True
    actions = {item["target"]: item for item in payload["actions"]}

    if cursor_present:
        _assert_installed(actions, ".cursor/rules/vibecleaner.mdc", tmp_path / ".cursor" / "rules" / "vibecleaner.mdc")
    else:
        assert ".cursor/rules/vibecleaner.mdc" not in actions
    _assert_installed(actions, ".claude/rules/vibecleaner.md", tmp_path / ".claude" / "rules" / "vibecleaner.md")
    assert actions[".agents/plugins/vibecleaner"]["status"] == "created"
    assert actions[".github/workflows/vibecleaner.yml"]["status"] == "created"
    assert ".git/hooks/pre-push" not in actions

    hook_script = tmp_path / ".agents" / "plugins" / "vibecleaner" / "scripts" / "vibecleaner-hook.sh"
    assert hook_script.is_file()
    assert bool(hook_script.stat().st_mode & stat.S_IXUSR)


def test_init_fails_closed_on_missing_directory(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    missing = tmp_path / "does-not-exist"
    assert main(["init", str(missing)]) == 2
    assert "not a directory" in capsys.readouterr().err


def test_bare_vibecleaner_defaults_to_scan_without_breaking_unknown_commands(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    (tmp_path / "app.py").write_text("def double(x: int) -> int:\n    return x * 2\n", encoding="utf-8")
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)

    old_cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        # Bare `vibecleaner` with no args scans `.` and writes VIBECLEANER_REPORT.md
        assert main([]) == 0
        assert "VibeCleaner" in capsys.readouterr().out
        assert (tmp_path / "VIBECLEANER_REPORT.md").is_file()
        (tmp_path / "VIBECLEANER_REPORT.md").unlink()

        # Bare `vibecleaner --quiet --mode offline` scans `.`
        assert main(["--quiet", "--mode", "offline", "--no-report"]) == 0
        assert capsys.readouterr().out.strip() == "VIBECLEANER: PASS"
    finally:
        os.chdir(old_cwd)

    # Bare `vibecleaner <path> --quiet` scans `<path>`
    assert main([str(tmp_path), "--quiet", "--mode", "offline", "--no-report"]) == 0
    assert capsys.readouterr().out.strip() == "VIBECLEANER: PASS"

    # Unknown non-path command still fails closed with exit 2
    assert main(["not-a-real-subcommand"]) == 2
    capsys.readouterr()

    # Help still prints top-level subcommands including `init`
    assert main(["--help"]) == 0
    help_out = " ".join(capsys.readouterr().out.split())
    assert "init" in help_out
    assert "Bare 'vibecleaner' runs 'vibecleaner scan .'" in help_out


def _try_editor_dir(path: Path) -> bool:
    try:
        path.mkdir()
    except OSError as exc:
        if exc.errno not in (errno.EPERM, errno.EACCES):
            raise
        return False
    return True


def _assert_installed(actions: dict[str, dict[str, str]], label: str, path: Path) -> None:
    action = actions[label]
    if action["status"] == "created":
        assert path.is_file()
        return
    assert action["status"] == "skipped"
    assert "not permitted" in action["detail"]
