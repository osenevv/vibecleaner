"""Regression tests for the audit findings on scan, fix, and interface workflow."""

from __future__ import annotations

import os
import re
from pathlib import Path

import pytest
from pathcmd import install_path_command

from vibecleaner.cleanup import fix_tree
from vibecleaner.collector import collect
from vibecleaner.deslop import detect_repo_deslop
from vibecleaner.imports import missing_imports
from vibecleaner.models import Language, SourceFile
from vibecleaner.surface_rules import apply_design
from vibecleaner.workflow.interface import MANDATORY_AGENT_RULES


def test_missing_dependency_skips_repos_without_a_manifest(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("from fastapi import FastAPI\napp = FastAPI()\n", encoding="utf-8")
    assert missing_imports(tmp_path, collect(tmp_path).files) == []
    (tmp_path / "pyproject.toml").write_text("[project]\nname = 'demo'\ndependencies = []\n", encoding="utf-8")
    findings = missing_imports(tmp_path, collect(tmp_path).files)
    assert [f.symbol for f in findings] == ["fastapi"]


def test_legacy_fallback_does_not_flag_private_helpers_across_files() -> None:
    a = SourceFile("pkg/deslop.py", Path("pkg/deslop.py"), Language.PYTHON, "def _python_unused():\n    return 1\n")
    b = SourceFile("pkg/det.py", Path("pkg/det.py"), Language.PYTHON, "def _deprecated_python():\n    return 2\n")
    c = SourceFile("pkg/struct.py", Path("pkg/struct.py"), Language.PYTHON, "def _python():\n    return 3\n")
    assert detect_repo_deslop([a, b, c]) == []


def test_fix_keeps_public_function_after_removing_debug_statement(tmp_path: Path) -> None:
    (tmp_path / "pricing.py").write_text(
        "def price(n: int) -> int:\n"
        "    return n * 5\n\n"
        "def total(n: int) -> int:\n"
        "    breakpoint()\n"
        "    return price(n)\n",
        encoding="utf-8",
    )
    fix_tree(tmp_path, use_host=False)
    text = (tmp_path / "pricing.py").read_text(encoding="utf-8")
    assert "breakpoint" not in text
    assert "def total(n: int) -> int:" in text
    assert "def price(n: int) -> int:" in text


def test_fix_removes_full_lorem_sentence_and_avoids_hex_empty_rules_and_double_primary(tmp_path: Path) -> None:
    html = (
        "<!DOCTYPE html><html><head><style>"
        ".hero { background: linear-gradient(90deg, #6366f1, #a855f7); }"
        ".card { color: #333333; }"
        "</style></head><body>"
        "<p>Lorem ipsum dolor sit amet.</p>"
        "<button class='btn primary'>Buy</button>"
        "<button class='btn primary'>Learn more</button>"
        "</body></html>\n"
    )
    (tmp_path / "index.html").write_text(html, encoding="utf-8")
    fix_tree(tmp_path, use_host=False)
    out = (tmp_path / "index.html").read_text(encoding="utf-8")
    assert "lorem" not in out.lower()
    assert "dolor sit amet" not in out.lower()
    assert not re.search(r"#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})\b", out)
    assert ".hero{" not in out.replace(" ", "")
    assert out.count("primary") == 1
    assert "secondary" in out


def test_apply_design_css_uses_oklch_and_drops_empty_rules() -> None:
    css = ".hero { background: linear-gradient(red, blue); }\n.card { color: #111111; }\n"
    out = apply_design(css, ".css")
    assert not re.search(r"#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})\b", out)
    assert "oklch(" in out
    assert ".hero" not in out
    assert ".card" in out


def test_fix_writes_interface_instruction_to_file_once_even_for_clean_page(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "index.html").write_text(
        "<!DOCTYPE html><html><head><meta name='viewport' content='width=device-width, initial-scale=1'></head>"
        "<body><h1>Invoice</h1><button>Pay $10</button></body></html>\n",
        encoding="utf-8",
    )
    outside = tmp_path.parent / "host-bin"
    log = outside / "argv.log"
    install_path_command(
        outside,
        "claude",
        "import pathlib, sys\n"
        f"path = pathlib.Path({str(log)!r})\n"
        "prior = path.read_text(encoding='utf-8') if path.exists() else ''\n"
        "path.write_text(prior + '\\n'.join(sys.argv) + '\\n---\\n', encoding='utf-8')\n",
    )
    monkeypatch.setenv("VIBECLEANER_HOST", "claude-code")
    monkeypatch.setenv("PATH", f"{outside}{os.pathsep}{os.environ.get('PATH', '')}")
    report = fix_tree(tmp_path, use_host=True)
    assert report.host == "ran"
    recorded = log.read_text(encoding="utf-8")
    assert recorded.count("\n---\n") == 1
    assert "Follow the instruction at " in recorded
    assert len(recorded) < 2000


def test_mandatory_agent_rules_include_no_slogans_clause() -> None:
    assert "Keep documentation concise and factual. Do not use punchy slogans or promotional language." in MANDATORY_AGENT_RULES


def test_toml_deps_ignores_authors_and_metadata() -> None:
    from vibecleaner.imports import _toml_deps

    toml = (
        '[project]\n'
        'name = "vibecleaner"\n'
        'authors = [{ name = "Vladimir Osenev" }]\n'
        'dependencies = ["rich>=13.7", "pathspec>=0.12"]\n'
        '[project.optional-dependencies]\n'
        'dev = ["pytest>=8"]\n'
    )
    deps = _toml_deps(toml)
    assert deps == {"rich", "pathspec", "pytest"}
    assert "vladimir" not in deps


def test_browser_check_returns_clean_result_without_playwright(tmp_path: Path) -> None:
    from vibecleaner.fix_contract import Verdict
    from vibecleaner.runtime.browser import check_html_file_in_browser

    page = tmp_path / "index.html"
    page.write_text("<!DOCTYPE html><html><body><h1>Hi</h1></body></html>\n", encoding="utf-8")
    result = check_html_file_in_browser(page)
    assert result.verdict in {Verdict.PASS, Verdict.ESCALATE}
