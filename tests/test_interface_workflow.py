"""A page copies the five interface skills into one instruction and runs it once."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest
from gitutil import init_git
from pathcmd import install_path_command

from vibecleaner.fix_contract import RunOutcome
from vibecleaner.run import RunOptions, start
from vibecleaner.workflow.documents import SKILLS, THIRD_PARTY
from vibecleaner.workflow.interface import (
    INTERFACE_SKILLS,
    MANDATORY_AGENT_RULES,
    interface_instruction,
    page_paths,
)


def test_skills_follow_the_workflow_without_overlap() -> None:
    assert INTERFACE_SKILLS == ("ground", "words", "page", "motion", "check")
    text = interface_instruction("index.html")
    positions = [text.index(f"----- {name} -----") for name in INTERFACE_SKILLS]
    assert positions == sorted(positions)
    for name in INTERFACE_SKILLS:
        body = SKILLS[name]
        assert f"name: {name}" in body.split("---", 2)[1]
        assert body.strip() in text
    owned = {
        "ground": "ThinkUI: not connected",
        "words": "Use sentence case.",
        "page": "Shadows only on things that float.",
        "motion": "transform: scale(0.97)",
        "check": "icon-only button has an `aria-label`",
    }
    for name, rule in owned.items():
        assert text.count(rule) == 1
        assert rule in SKILLS[name]
    for old in (
        "anti-ui-slop",
        "thinkui",
        "taste-skill",
        "emil-design-eng",
        "web-design-guidelines",
    ):
        assert f"----- {old} -----" not in text
    assert "There is no skill folder to open." in text
    assert "Copyright (c) 2026 Emil Kowalski" in THIRD_PARTY["emil-design-eng/LICENSE"]
    assert "Apache License" in THIRD_PARTY["anti-ui-slop/LICENSE"]
    assert "Copyright (c) 2026 Leonxlnx" in THIRD_PARTY["taste-skill/LICENSE"]
    assert text.index("----- check -----") < text.index("----- third-party notices -----")


def test_pages_include_a_screen_and_skip_dependencies(tmp_path: Path) -> None:
    (tmp_path / "index.html").write_text("<h1>Price</h1>\n", encoding="utf-8")
    (tmp_path / "app.tsx").write_text("export const App = () => null\n", encoding="utf-8")
    nested = tmp_path / "node_modules" / "pkg"
    nested.mkdir(parents=True)
    (nested / "index.html").write_text("<h1>dep</h1>\n", encoding="utf-8")
    (tmp_path / "main.py").write_text("print('ok')\n", encoding="utf-8")
    assert page_paths(tmp_path) == ("app.tsx", "index.html")


def test_a_page_without_a_host_asks_for_one(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _commit_page(tmp_path)
    monkeypatch.delenv("VIBECLEANER_HOST", raising=False)
    result = start(tmp_path, RunOptions(local=False, sandbox="host"), lambda _line: None)
    assert result.outcome is RunOutcome.NEEDS_YOU
    assert "ground" in result.questions[0]
    assert "check" in result.questions[0]


def test_a_page_runs_one_instruction_containing_every_skill(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _commit_page(tmp_path)
    outside = tmp_path.parent / "host"
    log = outside / "skills.log"
    bin_dir = outside / "bin"
    install_path_command(
        bin_dir,
        "claude",
        "import pathlib, sys\n"
        f"path = pathlib.Path({str(log)!r})\n"
        "prior = path.read_text(encoding='utf-8') if path.exists() else ''\n"
        "path.write_text(prior + '\\n'.join(sys.argv) + '\\n---\\n', encoding='utf-8')\n",
    )
    monkeypatch.setenv("VIBECLEANER_HOST", "claude-code")
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}")
    result = start(tmp_path, RunOptions(local=False, sandbox="host"), lambda _line: None)
    assert result.outcome is RunOutcome.READY
    assert "interface instruction ran" in result.summary
    recorded = log.read_text(encoding="utf-8")
    assert recorded.count("\n---\n") == 1
    instruction = Path(recorded.split("Follow the instruction at ", 1)[1].split(". ", 1)[0])
    text = instruction.read_text(encoding="utf-8")
    positions = [text.index(f"----- {name} -----") for name in INTERFACE_SKILLS]
    assert positions == sorted(positions)
    for name in INTERFACE_SKILLS:
        assert SKILLS[name].strip() in text
    assert "Do not run vibecleaner." in text
    assert text.index("These rules are mandatory.") < text.index("----- ground -----")
    for rule in MANDATORY_AGENT_RULES:
        assert rule in text
    assert "Do not write the PR description yourself." in recorded
    assert "Do not reply to the reviewer's comment yourself." in recorded


def _commit_page(root: Path) -> None:
    init_git(root)
    (root / "index.html").write_text(
        "<!DOCTYPE html><html><body><h1>Price</h1><button>Save</button></body></html>\n",
        encoding="utf-8",
    )
    subprocess.run(["git", "add", "index.html"], cwd=root, check=True)
    subprocess.run(["git", "commit", "-qm", "page"], cwd=root, check=True, env=_git_env())


def _git_env() -> dict[str, str]:
    env = dict(os.environ)
    env.setdefault("GIT_AUTHOR_NAME", "VibeCleaner")
    env.setdefault("GIT_AUTHOR_EMAIL", "vibecleaner@example.com")
    env.setdefault("GIT_COMMITTER_NAME", "VibeCleaner")
    env.setdefault("GIT_COMMITTER_EMAIL", "vibecleaner@example.com")
    return env
