"""Start returns ready, or a question, without touching a dirty tree."""

from __future__ import annotations

import subprocess
from pathlib import Path

from gitutil import init_git

from vibecleaner.cli import main
from vibecleaner.fix_contract import RunOutcome
from vibecleaner.run import RunOptions, start


def _options() -> RunOptions:
    return RunOptions(local=False, sandbox="host")


def test_readme_only_repo_is_ready(tmp_path: Path) -> None:
    init_git(tmp_path)
    (tmp_path / "README.md").write_text("A library.\n", encoding="utf-8")
    subprocess.run(["git", "add", "README.md"], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-qm", "docs"], cwd=tmp_path, check=True)
    result = start(tmp_path, _options(), lambda _line: None)
    assert result.outcome is RunOutcome.READY
    assert (tmp_path / "VIBECLEANER_RUN.md").is_file()


def test_dirty_tree_is_left_untouched(tmp_path: Path) -> None:
    init_git(tmp_path)
    (tmp_path / "README.md").write_text("A library.\n", encoding="utf-8")
    subprocess.run(["git", "add", "README.md"], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-qm", "docs"], cwd=tmp_path, check=True)
    extra = tmp_path / "notes.txt"
    extra.write_text("still editing\n", encoding="utf-8")
    result = start(tmp_path, _options(), lambda _line: None)
    assert result.outcome is RunOutcome.NEEDS_YOU
    assert result.questions
    assert extra.read_text(encoding="utf-8") == "still editing\n"


def test_secret_without_a_team_asks_the_user(tmp_path: Path) -> None:
    init_git(tmp_path)
    secret = "sk_" + "live_" + "a1b2c3d4e5f6g7h8i9j0"
    (tmp_path / "app.py").write_text(f'KEY = "{secret}"\n', encoding="utf-8")
    subprocess.run(["git", "add", "app.py"], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-qm", "add key"], cwd=tmp_path, check=True)
    result = start(tmp_path, _options(), lambda _line: None)
    assert result.outcome is RunOutcome.NEEDS_YOU
    assert result.evidence
    assert "app.py" in result.evidence[0].summary


def test_fix_and_run_mean_start(tmp_path: Path) -> None:
    init_git(tmp_path)
    (tmp_path / "README.md").write_text("A library.\n", encoding="utf-8")
    subprocess.run(["git", "add", "README.md"], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-qm", "docs"], cwd=tmp_path, check=True)
    assert main(["fix", str(tmp_path), "--sandbox", "host", "--no-local", "--json"]) == 0
    (tmp_path / "VIBECLEANER_RUN.md").unlink()
    assert main(["run", str(tmp_path), "--sandbox", "host", "--no-local", "--json"]) == 0


def test_cli_start_on_a_readme_repo_exits_0(tmp_path: Path) -> None:
    init_git(tmp_path)
    (tmp_path / "README.md").write_text("A library.\n", encoding="utf-8")
    subprocess.run(["git", "add", "README.md"], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-qm", "docs"], cwd=tmp_path, check=True)
    assert main(["start", str(tmp_path), "--sandbox", "host", "--no-local", "--json"]) == 0
