"""End-to-end tests for plain-English output, --prompt, --copy, and --autofix."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from pathcmd import install_path_command
from vibecleaner.cli import main


def _write_secret_repo(repo: Path) -> str:
    repo.mkdir(parents=True, exist_ok=True)
    fake_key = "sk_" + "live_" + "0123456789abcdef01234567"
    (repo / "app.py").write_text(f'STRIPE_KEY = "{fake_key}"\n', encoding="utf-8")
    return fake_key


def test_default_output_and_prompt_flag_explain_risks_and_redact_secrets(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repo = tmp_path / "repo"
    fake_key = _write_secret_repo(repo)

    assert main([str(repo), "--mode", "offline", "--no-report", "--no-cache"]) == 1
    full_out = capsys.readouterr().out
    assert "Plain-English summary:" in full_out
    assert "Copy and paste this into your AI coding agent" in full_out
    assert "vibecleaner --autofix" in full_out
    assert fake_key not in full_out

    assert main([str(repo), "--prompt", "--mode", "offline", "--no-report", "--no-cache"]) == 1
    prompt_out = capsys.readouterr().out
    assert prompt_out.startswith("Fix these 1 VibeCleaner blocker")
    assert "app.py:1 [CRITICAL D1.hardcoded_secret]" in prompt_out
    assert "Do not disable VibeCleaner checks" in prompt_out
    assert fake_key not in prompt_out


def test_autofix_runs_agent_fixes_code_and_rescan_passes(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repo = tmp_path / "repo"
    fake_key = _write_secret_repo(repo)
    seen_prompt = tmp_path / "seen_prompt.txt"

    agent_script = tmp_path / "fixer.py"
    agent_script.write_text(
        "import pathlib, sys\n"
        f"pathlib.Path({str(seen_prompt)!r}).write_text(sys.argv[-1], encoding='utf-8')\n"
        "pathlib.Path('app.py').write_text('import os\\nSTRIPE_KEY = os.environ[\"STRIPE_KEY\"]\\n', encoding='utf-8')\n",
        encoding="utf-8",
    )

    rc = main(
        [
            str(repo),
            "--autofix",
            "--agent",
            f"{sys.executable} {agent_script}",
            "--mode",
            "offline",
            "--no-report",
            "--no-cache",
        ]
    )
    out = capsys.readouterr().out
    assert rc == 0
    assert "VIBECLEANER AUTOFIX: FIXED in 1 round(s)" in out
    assert "PASS" in out

    prompt_received = seen_prompt.read_text(encoding="utf-8")
    assert "app.py:1 [CRITICAL D1.hardcoded_secret]" in prompt_received
    assert fake_key not in prompt_received


def test_autofix_fails_closed_when_agent_does_not_fix_or_exits_nonzero(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repo = tmp_path / "repo"
    _write_secret_repo(repo)

    noop_agent = tmp_path / "noop.py"
    noop_agent.write_text("import sys\nsys.exit(0)\n", encoding="utf-8")
    rc = main(
        [
            str(repo),
            "--autofix",
            "--agent",
            f"{sys.executable} {noop_agent}",
            "--mode",
            "offline",
            "--no-report",
            "--no-cache",
        ]
    )
    capsys.readouterr()
    assert rc == 1

    crash_agent = tmp_path / "crash.py"
    crash_agent.write_text("import sys\nsys.exit(3)\n", encoding="utf-8")
    rc = main(
        [
            str(repo),
            "--autofix",
            "--agent",
            f"{sys.executable} {crash_agent}",
            "--mode",
            "offline",
            "--no-report",
            "--no-cache",
        ]
    )
    out = capsys.readouterr().out
    assert rc == 2
    assert "exited with code 3" in out


def test_autofix_falls_back_to_clipboard_when_no_agent_cli_on_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repo = tmp_path / "repo"
    _write_secret_repo(repo)

    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    captured_clip = tmp_path / "clipboard.txt"
    install_path_command(
        fake_bin,
        "pbcopy",
        "import pathlib, sys\n"
        f"pathlib.Path({str(captured_clip)!r}).write_text(sys.stdin.read(), encoding='utf-8')\n",
    )
    monkeypatch.setenv("PATH", str(fake_bin))

    rc = main([str(repo), "--autofix", "--mode", "offline", "--no-report", "--no-cache"])
    out = capsys.readouterr().out
    assert rc == 1
    assert "Copied the fix prompt to your clipboard via pbcopy" in out
    assert "app.py:1 [CRITICAL D1.hardcoded_secret]" in captured_clip.read_text(encoding="utf-8")


def test_max_fix_rounds_validation(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main([str(tmp_path), "--max-fix-rounds", "0", "--no-report"]) == 2
    assert "--max-fix-rounds" in capsys.readouterr().err
    assert main([str(tmp_path), "--max-fix-rounds", "9", "--no-report"]) == 2
    assert "--max-fix-rounds" in capsys.readouterr().err
