"""Tests for multi-judge routing, sandbox images, start fixer branch commit, and proof fixtures."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from gitutil import init_git
from pathcmd import install_path_command

from vibecleaner.cleanup import fix_tree
from vibecleaner.decision_judge import DecisionAPIError, GeminiDecisionBackend, select_backend
from vibecleaner.fix_contract import RunOutcome
from vibecleaner.judge_backends import OpenAIDecisionBackend, SystemOneDecisionBackend, resolve_judge_route
from vibecleaner.offline_heuristics import OfflineHeuristicBackend
from vibecleaner.run import RunOptions, start
from vibecleaner.verify.sandbox import choose_image


def _clear_judge_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in (
        "VIBECLEANER_JUDGE",
        "TYPESAFE_API_KEY",
        "JEV_API_KEY",
        "GEMINI_API_KEY",
        "GOOGLE_API_KEY",
        "OPENAI_API_KEY",
        "CLOUDFLARE_API_TOKEN",
        "CLOUDFLARE_ACCOUNT_ID",
        "PERPLEXITY_API_KEY",
        "LIQUID_API_KEY",
        "AZURE_OPENAI_API_KEY",
        "AZURE_OPENAI_ENDPOINT",
        "LAYA_BASE_URL",
    ):
        monkeypatch.delenv(var, raising=False)


def test_judge_routing_selects_non_gemini_providers_without_gemini_key(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_judge_env(monkeypatch)
    assert isinstance(select_backend("auto"), OfflineHeuristicBackend)
    with pytest.raises(DecisionAPIError):
        select_backend("live")

    monkeypatch.setenv("TYPESAFE_API_KEY", "ts-key")
    backend = select_backend("live")
    assert isinstance(backend, SystemOneDecisionBackend)
    assert backend.name == "jev-latest"

    _clear_judge_env(monkeypatch)
    monkeypatch.setenv("OPENAI_API_KEY", "oa-key")
    backend = select_backend("live")
    assert isinstance(backend, OpenAIDecisionBackend)
    assert backend.name == "gpt-6-luna"
    assert backend.calibrated is False

    _clear_judge_env(monkeypatch)
    monkeypatch.setenv("PERPLEXITY_API_KEY", "px-key")
    backend = select_backend("live")
    assert isinstance(backend, SystemOneDecisionBackend)
    assert backend.name == "pplx-decider-latest"

    monkeypatch.setenv("GEMINI_API_KEY", "gm-key")
    monkeypatch.setenv("VIBECLEANER_JUDGE", "gemini")
    assert isinstance(select_backend("live"), GeminiDecisionBackend)
    assert resolve_judge_route({"LAYA_BASE_URL": "http://localhost:8080"}).provider == "laya"


def test_sandbox_choose_image_covers_go_rust_and_jvm(tmp_path: Path) -> None:
    go_repo = tmp_path / "go"
    go_repo.mkdir()
    (go_repo / "go.mod").write_text("module example.com/demo\n", encoding="utf-8")
    assert choose_image(go_repo).startswith("golang:")

    rust_repo = tmp_path / "rust"
    rust_repo.mkdir()
    (rust_repo / "Cargo.toml").write_text("[package]\nname = 'demo'\n", encoding="utf-8")
    assert choose_image(rust_repo).startswith("rust:")

    jvm_repo = tmp_path / "jvm"
    jvm_repo.mkdir()
    (jvm_repo / "pom.xml").write_text("<project/>\n", encoding="utf-8")
    assert "temurin" in choose_image(jvm_repo)


def _commit_failing_py_repo(root: Path) -> None:
    init_git(root)
    (root / "pytest.ini").write_text("[pytest]\npythonpath = .\n", encoding="utf-8")
    (root / ".vibecleaner").mkdir(exist_ok=True)
    (root / ".vibecleaner" / "config.json").write_text(
        json.dumps({"test": f"{Path(sys.executable).as_posix()} -m pytest -q"}) + "\n",
        encoding="utf-8",
    )
    (root / "calc.py").write_text("def double(n: int) -> int:\n    return n + 1\n", encoding="utf-8")
    (root / "tests").mkdir()
    (root / "tests" / "test_calc.py").write_text(
        "from calc import double\n\ndef test_double() -> None:\n    assert double(3) == 6\n",
        encoding="utf-8",
    )
    subprocess.run(["git", "add", "."], cwd=root, check=True)
    subprocess.run(["git", "commit", "-qm", "init"], cwd=root, check=True)


def test_start_commits_honest_fix_to_new_branch_and_rejects_tamper(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "honest"
    repo.mkdir()
    _commit_failing_py_repo(repo)
    bin_dir = tmp_path / "bin-honest"
    install_path_command(
        bin_dir,
        "claude",
        "from pathlib import Path\n"
        "Path('calc.py').write_text('def double(n: int) -> int:\\n    return n * 2\\n', encoding='utf-8')\n",
    )
    monkeypatch.setenv("VIBECLEANER_HOST", "claude-code")
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}")
    result = start(repo, RunOptions(local=False, sandbox="host"), lambda _line: None)
    assert result.outcome is RunOutcome.FIXED
    assert result.branch is not None and result.branch.startswith("vibecleaner/fix-")
    assert len(result.commits) == 1
    assert "return n + 1" in (repo / "calc.py").read_text(encoding="utf-8")

    tamper_repo = tmp_path / "tamper"
    tamper_repo.mkdir()
    _commit_failing_py_repo(tamper_repo)
    tamper_bin = tmp_path / "bin-tamper"
    install_path_command(
        tamper_bin,
        "claude",
        "from pathlib import Path\n"
        "Path('tests/test_calc.py').write_text('def test_double():\\n    pass\\n', encoding='utf-8')\n",
    )
    monkeypatch.setenv("PATH", f"{tamper_bin}{os.pathsep}{os.environ.get('PATH', '')}")
    rejected = start(tamper_repo, RunOptions(local=False, sandbox="host"), lambda _line: None)
    assert rejected.outcome is RunOutcome.NEEDS_YOU
    assert "tampered" in rejected.summary.lower()


def test_proof_fixtures_exist_and_fix_cleanly_on_copy(tmp_path: Path) -> None:
    fixtures = Path(__file__).resolve().parent.parent / "benchmarks" / "slop"
    assert (fixtures / "app" / "index.html").is_file()
    assert (fixtures / "app" / "holdout.html").is_file()
    assert (fixtures / "cli" / "cli.py").is_file()
    assert (fixtures / "blind" / "labels.json").is_file()

    copy = tmp_path / "app"
    shutil.copytree(fixtures / "app", copy)
    first = fix_tree(copy, use_host=False)
    assert first.changed
    second = fix_tree(copy, use_host=False)
    assert second.changed == ()
    html = (copy / "index.html").read_text(encoding="utf-8")
    assert "linear-gradient" not in html
    assert html.count("primary") == 1
