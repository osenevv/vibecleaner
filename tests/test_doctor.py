"""Tests for `vibecleaner doctor` environment and repo diagnostics."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from vibecleaner.cli import main
from vibecleaner.doctor import render_doctor_text, run_doctor


def test_doctor_healthy_repo_and_json_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    (tmp_path / ".vibecleanerignore").write_text("tests/\n", encoding="utf-8")

    rc = main(["doctor", str(tmp_path), "--json"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True
    by_name = {item["name"]: item for item in payload["checks"]}
    assert by_name["python"]["status"] == "ok"
    assert by_name["layer2-api"]["status"] == "ok"
    assert "GEMINI_API_KEY" in by_name["layer2-api"]["detail"]
    assert by_name["repo-config"]["status"] == "ok"

    report = run_doctor(tmp_path)
    rendered = render_doctor_text(report)
    assert "VibeCleaner doctor" in rendered
    assert "repo-config" in rendered


def test_doctor_reports_broken_rules_or_config_as_error(tmp_path: Path) -> None:
    vc = tmp_path / ".vibecleaner"
    vc.mkdir()
    (vc / "rules.json").write_text("{not valid json", encoding="utf-8")
    assert main(["doctor", str(tmp_path)]) == 1

    (vc / "rules.json").write_text('{"version": 1, "rules": []}', encoding="utf-8")
    (vc / "config.json").write_text("[]", encoding="utf-8")
    assert main(["doctor", str(tmp_path)]) == 1

    (vc / "config.json").write_text('{"test": "pytest -q"}', encoding="utf-8")
    assert main(["doctor", str(tmp_path)]) == 0


def test_doctor_missing_directory_returns_error(tmp_path: Path) -> None:
    missing = tmp_path / "does-not-exist"
    assert main(["doctor", str(missing)]) == 1
