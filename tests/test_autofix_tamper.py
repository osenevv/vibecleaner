from __future__ import annotations

import sys
from pathlib import Path

from vibeguard.cli import main


def _write_vulnerable_repo(root: Path) -> None:
    (root / "app.py").write_text(
        "from fastapi import FastAPI\n"
        "from fastapi.middleware.cors import CORSMiddleware\n\n"
        "app = FastAPI()\n"
        "app.add_middleware(CORSMiddleware, allow_origins=['*'], allow_credentials=True)\n\n"
        "def add(a: int, b: int) -> int:\n    return a + b\n",
        encoding="utf-8",
    )
    (root / "tests").mkdir()
    (root / "tests" / "test_app.py").write_text(
        "from app import add\n\ndef test_add() -> None:\n    assert add(1, 2) == 3\n",
        encoding="utf-8",
    )


def test_autofix_rejects_test_tampering(tmp_path: Path, capsys) -> None:
    _write_vulnerable_repo(tmp_path)
    tamper_agent = tmp_path / "tamper_agent.py"
    tamper_agent.write_text(
        "from pathlib import Path\n"
        "Path('tests/test_app.py').write_text('def test_add():\\n    pass\\n', encoding='utf-8')\n",
        encoding="utf-8",
    )

    code = main(
        [
            "scan",
            str(tmp_path),
            "--mode",
            "offline",
            "--no-cache",
            "--no-report",
            "--autofix",
            "--agent",
            f"{sys.executable} {tamper_agent}",
        ]
    )

    captured = capsys.readouterr()
    assert code == 2
    assert "tampering" in captured.err.lower()


def test_autofix_allows_honest_source_fix(tmp_path: Path, capsys) -> None:
    _write_vulnerable_repo(tmp_path)
    honest_agent = tmp_path / "honest_agent.py"
    honest_agent.write_text(
        "from pathlib import Path\n"
        "Path('app.py').write_text("
        "'from fastapi import FastAPI\\n"
        "from fastapi.middleware.cors import CORSMiddleware\\n\\n"
        "app = FastAPI()\\n"
        "app.add_middleware(CORSMiddleware, allow_origins=[\"https://app.example.com\"], allow_credentials=True)\\n\\n"
        "def add(a: int, b: int) -> int:\\n    return a + b\\n', encoding='utf-8')\n",
        encoding="utf-8",
    )

    code = main(
        [
            "scan",
            str(tmp_path),
            "--mode",
            "offline",
            "--no-cache",
            "--no-report",
            "--autofix",
            "--agent",
            f"{sys.executable} {honest_agent}",
        ]
    )

    captured = capsys.readouterr()
    assert code == 0
    assert "VIBEGUARD AUTOFIX: FIXED" in captured.out
