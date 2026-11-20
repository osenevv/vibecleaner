"""Headless host CLIs share one argv path with --autofix."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from pathcmd import install_path_command
from vibecleaner.agents.hosts import host_from_name, preset_argv
from vibecleaner.agents.team import describe_team, select_team
from vibecleaner.fix_contract import ProviderError
from vibecleaner.prompt_fix import run_agent_fix

_HOSTS = (
    ("claude-code", "claude"),
    ("codex", "codex"),
    ("antigravity", "agy"),
)


def _install_cli(bin_dir: Path, name: str, record: Path) -> None:
    install_path_command(
        bin_dir,
        name,
        "import pathlib, sys\n"
        f"pathlib.Path({str(record)!r}).write_text("
        f"'\\n'.join([{name!r}, *sys.argv[1:]]) + '\\n', encoding='utf-8')\n"
        "pathlib.Path('edited.txt').write_text('patched\\n', encoding='utf-8')\n",
    )


def test_hosts_run_in_the_worktree_with_verified_flags(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    work = tmp_path / "work"
    work.mkdir()
    record = tmp_path / "argv.txt"
    for _host_name, preset in _HOSTS:
        _install_cli(bin_dir, preset, record)
    monkeypatch.setenv("PATH", str(bin_dir))
    instructions = "fix the checkout bug"
    for host_name, preset in _HOSTS:
        result = host_from_name(host_name).run_task(work, instructions, timeout_s=5)
        assert result.ok
        assert result.command == tuple(preset_argv(preset, instructions))
        _assert_recorded(record, preset_argv(preset, instructions))
        assert (work / "edited.txt").read_text(encoding="utf-8") == "patched\n"
    assert preset_argv("claude", instructions) == [
        "claude",
        "-p",
        instructions,
        "--permission-mode",
        "acceptEdits",
    ]
    assert preset_argv("codex", instructions) == ["codex", "exec", instructions]
    assert preset_argv("agy", instructions) == ["agy", "-p", instructions]
    outcome = run_agent_fix(work, instructions, agent="claude")
    assert outcome.status == "ran"
    _assert_recorded(record, preset_argv("claude", instructions))


def _assert_recorded(record: Path, argv: list[str]) -> None:
    lines = record.read_text(encoding="utf-8").splitlines()
    assert Path(lines[0]).name == argv[0]
    assert lines[1:] == argv[1:]


def test_host_timeout_and_missing_binary(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    work = tmp_path / "work"
    work.mkdir()
    install_path_command(bin_dir, "claude", "while True:\n    pass\n")
    monkeypatch.setenv("PATH", str(bin_dir))
    result = host_from_name("claude-code").run_task(work, "wait", timeout_s=0.4)
    assert result.timed_out
    assert result.returncode == 124
    empty = tmp_path / "empty"
    empty.mkdir()
    monkeypatch.setenv("PATH", str(empty))
    with pytest.raises(ProviderError, match="not found"):
        host_from_name("codex").run_task(work, "fix", timeout_s=2)


def test_host_is_taken_from_env_not_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    install_path_command(bin_dir, "claude", "raise SystemExit(0)\n")
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}")
    monkeypatch.delenv("VIBECLEANER_HOST", raising=False)
    assert select_team(tmp_path, local=False, env={}).host is None
    team = select_team(tmp_path, local=False, env={"VIBECLEANER_HOST": "codex"})
    assert team.host is not None
    assert team.host.name == "codex"
    assert team.host.family == "openai"
    assert describe_team(team) == "Codex agents"
    judged = select_team(
        tmp_path,
        local=False,
        env={"VIBECLEANER_HOST": "claude-code", "GEMINI_API_KEY": "g", "OPENAI_API_KEY": "o"},
    )
    assert describe_team(judged) == "Claude Code agents, judged by 2 other models"
    assert describe_team(select_team(tmp_path, local=False, env={"VIBECLEANER_HOST": "antigravity"})) == (
        "Antigravity agents"
    )
    assert describe_team(select_team(tmp_path, local=False, env={"GEMINI_API_KEY": "g"})) == "Gemini"
    assert describe_team(select_team(tmp_path, local=False, env={})) == "No agent or model available"
    with pytest.raises(ProviderError, match="VIBECLEANER_HOST"):
        select_team(tmp_path, local=False, env={"VIBECLEANER_HOST": "cursor"})
