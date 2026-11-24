"""Mocks, manifests, behavior, high-risk files, duplicates, and one host task per finding."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from pathcmd import install_path_command

from vibecleaner.behavior import behavior_holds
from vibecleaner.cleanup import fix_tree
from vibecleaner.collector import collect
from vibecleaner.imports import missing_imports
from vibecleaner.mocks import production_mocks

_WIDE = """\
def widen(x, y):
    total = x + y
    total = total + 1
    total = total + 1
    total = total + 1
    total = total + 1
    total = total + 1
    total = total + 1
    total = total + 1
    return total


def copy_widen(a, b):
    total = a + b
    total = total + 1
    total = total + 1
    total = total + 1
    total = total + 1
    total = total + 1
    total = total + 1
    total = total + 1
    return total


def other(a, b):
    total = a + b
    total = total + 2
    total = total + 2
    total = total + 2
    total = total + 2
    total = total + 2
    total = total + 2
    total = total + 2
    return total
"""


def test_future_annotations_are_sampled_as_their_type() -> None:
    before = "from __future__ import annotations\ndef label(text: str) -> str:\n    return text\n"
    after = "from __future__ import annotations\ndef label(text: str) -> str:\n    return text.upper()\n"
    assert not behavior_holds(before, after)


def test_behavior_refuses_a_different_result_and_allows_a_comment() -> None:
    same = "def add(a, b):\n    return a + b\n"
    assert behavior_holds(same, "def add(a, b):\n    # qty is cents\n    return a + b\n")
    assert not behavior_holds(same, "def add(a, b):\n    return a + b + 1\n")
    assert behavior_holds(same, 'def add(a, b):\n    raise RuntimeError("stub: add ignores its input")\n')


def test_a_duplicate_body_becomes_a_call(tmp_path: Path) -> None:
    (tmp_path / "maths.py").write_text(_WIDE, encoding="utf-8")
    report = fix_tree(tmp_path, use_host=False)
    text = (tmp_path / "maths.py").read_text(encoding="utf-8")
    assert "def widen(x, y):" in text
    assert "def copy_widen(a, b):" in text
    assert "return widen(a, b)" in text
    assert "def other" in text
    assert "total = total + 2" in text
    assert report.changed == ("maths.py",)
    assert fix_tree(tmp_path, use_host=False).changed == ()
    assert behavior_holds(_WIDE, text)


def test_high_risk_file_is_not_edited(tmp_path: Path) -> None:
    original = "def charge(qty):\n    # TODO: implement the charge later\n    return qty\n"
    (tmp_path / "billing.py").write_text(original, encoding="utf-8")
    report = fix_tree(tmp_path, use_host=False)
    assert (tmp_path / "billing.py").read_text(encoding="utf-8") == original
    assert any("billing.py" in item for item in report.held)
    assert not report.clean


def test_production_mock_is_a_finding_and_a_library_mock_is_not(tmp_path: Path) -> None:
    (tmp_path / "billing.py").write_text("def charge(qty):\n    return qty\n", encoding="utf-8")
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_billing.py").write_text(
        "from unittest.mock import patch\n\n"
        "def test_charge():\n"
        "    with patch('billing.charge', return_value=0):\n"
        "        assert True\n",
        encoding="utf-8",
    )
    (tests / "test_http.py").write_text(
        "from unittest.mock import patch\n\n"
        "def test_live():\n"
        "    with patch('requests.get', return_value=None):\n"
        "        assert True\n",
        encoding="utf-8",
    )
    findings = production_mocks(collect(tmp_path).files)
    assert [finding.symbol for finding in findings] == ["billing.charge"]


def test_an_import_missing_from_the_manifest_is_a_finding(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        "[project]\nname = 'demo'\nversion = '0'\ndependencies = ['flask>=2']\n",
        encoding="utf-8",
    )
    (tmp_path / "app.py").write_text("import flask\nimport ghostpkg\nimport os\n", encoding="utf-8")
    (tmp_path / "billing.py").write_text("def charge(qty):\n    return qty\n", encoding="utf-8")
    (tmp_path / "use_billing.py").write_text("import billing\n", encoding="utf-8")
    (tmp_path / "optional.py").write_text(
        "from typing import TYPE_CHECKING\n"
        "if TYPE_CHECKING:\n"
        "    from google.genai.client import Client\n"
        "def load():\n"
        "    try:\n"
        "        import sqlalchemy\n"
        "    except ImportError:\n"
        "        return None\n"
        "    return sqlalchemy\n",
        encoding="utf-8",
    )
    findings = missing_imports(tmp_path, collect(tmp_path).files)
    assert [finding.symbol for finding in findings] == ["ghostpkg"]


def test_the_host_gets_one_finding_and_other_files_come_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "pyproject.toml").write_text("[project]\nname = 'demo'\ndependencies = []\n", encoding="utf-8")
    (tmp_path / "alpha.py").write_text("import ghostpkg\n", encoding="utf-8")
    (tmp_path / "beta.py").write_text("import otherghost\n", encoding="utf-8")
    outside = tmp_path.parent / "host-bin"
    log = outside / "host.log"
    install_path_command(
        outside,
        "claude",
        "import os, pathlib, sys\n"
        f"root = pathlib.Path({str(tmp_path)!r})\n"
        f"log = pathlib.Path({str(log)!r})\n"
        "text = '\\n'.join(sys.argv)\n"
        "prior = log.read_text(encoding='utf-8') if log.exists() else ''\n"
        "log.write_text(prior + text + '\\n---\\n', encoding='utf-8')\n"
        "(root / 'extra.py').write_text('x = 1\\n', encoding='utf-8')\n"
        "for path in root.glob('*.py'):\n"
        "    if path.name == 'extra.py':\n"
        "        continue\n"
        "    path.write_text(path.read_text(encoding='utf-8') + '\\n# host\\n', encoding='utf-8')\n",
    )
    monkeypatch.setenv("VIBECLEANER_HOST", "claude-code")
    monkeypatch.setenv("PATH", f"{outside}{os.pathsep}{os.environ.get('PATH', '')}")
    fix_tree(tmp_path, use_host=True)
    recorded = log.read_text(encoding="utf-8")
    assert recorded.count("\n---\n") == 2
    assert "ghostpkg" in recorded and "otherghost" in recorded
    assert "Fix only the finding below" in recorded
    assert not (tmp_path / "extra.py").exists()
    assert (tmp_path / "alpha.py").read_text(encoding="utf-8").count("# host") == 1
    assert (tmp_path / "beta.py").read_text(encoding="utf-8").count("# host") == 1
