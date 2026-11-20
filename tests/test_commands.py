"""deslop lanes, project-rule commands, and SARIF rule lists."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from vibeguard.cli import main
from vibeguard.commands import _lanes
from vibeguard.models import (
    PROJECT_RULE_PREFIX,
    RULES,
    Category,
    Finding,
    JudgeStats,
    RuleSpec,
    ScanResult,
    Severity,
    register_project_rule,
)
from vibeguard.reporter import to_sarif

_RETRY = (
    "def poll():\n"
    "    while True:\n"
    "        try:\n"
    "            return fetch()\n"
    "        except Exception:\n"
    "            log()\n"
)


def _project_ids() -> set[str]:
    return {rule_id for rule_id in RULES if rule_id.startswith(PROJECT_RULE_PREFIX)}


def _pattern_rule(rule_id: str, pattern: str, message: str, lane: str | None = None) -> dict[str, object]:
    rule: dict[str, object] = {
        "id": rule_id,
        "kind": "pattern",
        "pattern": pattern,
        "include": ["**"],
        "exclude": [".vibeguard/**"],
        "severity": "high",
        "category": "slop",
        "message": message,
    }
    if lane is not None:
        rule["lane"] = lane
    return rule


def _write_rules(root: Path, rules: list[dict[str, object]]) -> None:
    path = root / ".vibeguard" / "rules.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"version": 1, "rules": rules}), encoding="utf-8")


def _sarif_ids(path: Path) -> set[str]:
    document = json.loads(path.read_text(encoding="utf-8"))
    return {rule["id"] for rule in document["runs"][0]["tool"]["driver"]["rules"]}


def _scan(root: Path, sarif: Path) -> int:
    return main(
        [
            "scan",
            str(root),
            "--mode",
            "offline",
            "--no-cache",
            "--quiet",
            "--no-report",
            "--fail-on",
            "none",
            "--sarif",
            str(sarif),
        ]
    )


def test_lane_for_d8_project_rules_and_unknown_ids() -> None:
    findings = [
        Finding("D8.unbounded_retry", "a.py", 1, "retry"),
        Finding("D8.lock_not_released", "a.py", 2, "lock"),
        Finding("D8.retry_falls_through", "a.py", 3, "fall"),
        Finding("D9.duplicate_function", "a.py", 4, "dup"),
        Finding("D9.pointless_catch", "a.py", 5, "catch"),
        Finding("P.custom", "a.py", 6, "custom"),
        Finding("P.typed", "a.py", 7, "typed"),
        Finding("nope.unknown", "a.py", 8, "unknown"),
    ]
    lanes = _lanes(findings, {"P.typed": "weak-types"})
    assert [item.rule_id for item in lanes["defensive-code"]] == [
        "D8.unbounded_retry",
        "D8.lock_not_released",
        "D8.retry_falls_through",
        "D9.pointless_catch",
    ]
    assert [item.rule_id for item in lanes["dedupe"]] == ["D9.duplicate_function", "nope.unknown"]
    assert [item.rule_id for item in lanes["ai-slop"]] == ["P.custom"]
    assert [item.rule_id for item in lanes["weak-types"]] == ["P.typed"]


def test_deslop_help_shows_medium_default(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["deslop", "--help"]) == 0
    help_text = capsys.readouterr().out
    assert "--fail-on" in help_text
    assert "(default: medium)" in help_text


def test_deslop_puts_d8_in_defensive_code_and_honors_pattern_lane(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "spin.py").write_text(_RETRY, encoding="utf-8")
    (root / "app.py").write_text("WEAK_TOKEN = 1\nSLOP_TOKEN = 2\n", encoding="utf-8")
    _write_rules(
        root,
        [
            _pattern_rule("typed-token", "WEAK_TOKEN", "name the type", lane="weak-types"),
            _pattern_rule("slop-token", "SLOP_TOKEN", "placeholder"),
        ],
    )
    assert main(["deslop", str(root), "--json", "--fail-on", "none"]) == 0
    payload = json.loads(capsys.readouterr().out)
    defensive = {row["rule_id"] for row in payload["lanes"]["defensive-code"]}
    dedupe = {row["rule_id"] for row in payload["lanes"]["dedupe"]}
    weak = {row["rule_id"] for row in payload["lanes"]["weak-types"]}
    slop = {row["rule_id"] for row in payload["lanes"]["ai-slop"]}
    assert "D8.unbounded_retry" in defensive
    assert "D8.unbounded_retry" not in dedupe
    assert "P.typed-token" in weak
    assert "P.slop-token" in slop
    assert "P.typed-token" not in slop
    assert "P.slop-token" not in weak


def test_add_pattern_lane_flag_and_rule_list(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = tmp_path / "repo"
    (root / "app").mkdir(parents=True)
    (root / "app" / "page.py").write_text("useEffect()\n", encoding="utf-8")
    code = main(
        [
            "rule",
            "add-pattern",
            "no-effect",
            "--pattern",
            r"useEffect\s*\(",
            "--message",
            "no effect",
            "--include",
            "app/**",
            "--lane",
            "defensive-code",
            "--path",
            str(root),
        ]
    )
    assert code == 0
    saved = json.loads((root / ".vibeguard" / "rules.json").read_text(encoding="utf-8"))
    assert saved["rules"][0]["lane"] == "defensive-code"
    listed = capsys.readouterr().out
    assert "saved P.no-effect" in listed

    assert main(["rule", "list", "--path", str(root)]) == 0
    listing = capsys.readouterr().out
    assert "P.no-effect" in listing
    assert "pattern" in listing
    assert "1 hit(s)" in listing
    assert "no effect" in listing

    rejected = main(
        [
            "rule",
            "add-pattern",
            "bad-lane",
            "--pattern",
            "x",
            "--message",
            "no",
            "--lane",
            "not-a-lane",
            "--path",
            str(root),
        ]
    )
    assert rejected == 2
    assert "bad-lane" not in (root / ".vibeguard" / "rules.json").read_text(encoding="utf-8")


def test_preview_command_leaves_rules_unchanged(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_text("ALPHA_TOKEN = 1\n", encoding="utf-8")
    (root / "ui").mkdir()
    (root / "ui" / "panel.py").write_text("from ..lib.db import connect\n", encoding="utf-8")
    before = _project_ids()
    code = main(
        [
            "rule",
            "add-pattern",
            "preview-token",
            "--pattern",
            "ALPHA_TOKEN",
            "--message",
            "no",
            "--lane",
            "legacy",
            "--path",
            str(root),
            "--preview",
        ]
    )
    assert code == 0
    preview = capsys.readouterr().out
    assert "app.py:1" in preview
    assert "not saved" in preview
    assert not (root / ".vibeguard").exists()
    assert "P.preview-token" not in RULES
    assert _project_ids() == before

    boundary = main(
        [
            "rule",
            "add-boundary",
            "ui-no-db",
            "--from",
            "ui/**",
            "--forbid",
            "lib.db",
            "--message",
            "no db",
            "--path",
            str(root),
            "--preview",
        ]
    )
    assert boundary == 0
    boundary_out = capsys.readouterr().out
    assert "ui/panel.py:1" in boundary_out
    assert "not saved" in boundary_out
    assert not (root / ".vibeguard").exists()
    assert "P.ui-no-db" not in RULES
    assert _project_ids() == before


def test_broken_rules_file_exits_2(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_text("x = 1\n", encoding="utf-8")
    rules = root / ".vibeguard" / "rules.json"
    rules.parent.mkdir(parents=True)
    rules.write_text("{", encoding="utf-8")
    before = rules.read_bytes()
    commands = [
        ["scan", str(root), "--mode", "offline", "--no-cache", "--quiet", "--no-report"],
        ["deslop", str(root), "--json"],
        ["preflight", str(root), "--json"],
        ["rule", "list", "--path", str(root)],
        ["rule", "add-pattern", "still-bad", "--pattern", "x", "--message", "no", "--path", str(root)],
    ]
    for argv in commands:
        assert main(argv) == 2
        err = capsys.readouterr().err
        assert err.startswith("error:")
        assert "invalid JSON" in err
        assert rules.read_bytes() == before


def test_sarif_lists_only_active_project_rules() -> None:
    alpha = RuleSpec("P.stale-alpha", "P", "alpha", Category.SLOP, Severity.HIGH, 1, "fix alpha")
    beta = RuleSpec("P.active-beta", "P", "beta", Category.SLOP, Severity.LOW, 1, "fix beta")
    quiet = RuleSpec("P.active-quiet", "P", "quiet", Category.SLOP, Severity.LOW, 1, "fix quiet")
    register_project_rule(alpha)
    register_project_rule(beta)
    register_project_rule(quiet)
    result = ScanResult(
        root=Path("/repo"),
        findings=[Finding("P.active-beta", "b.py", 1, "beta")],
        files_scanned=1,
        judge=JudgeStats(),
        duration_s=0.0,
        project_rule_specs=(beta, quiet),
    )
    ids = {rule["id"] for rule in to_sarif(result)["runs"][0]["tool"]["driver"]["rules"]}
    assert "P.active-beta" in ids
    assert "P.active-quiet" in ids
    assert "P.stale-alpha" not in ids
    assert "D1.hardcoded_secret" in ids
    assert "D8.unbounded_retry" in ids

    from_finding = ScanResult(
        root=Path("/repo"),
        findings=[Finding("P.stale-alpha", "a.py", 2, "alpha")],
        files_scanned=1,
        judge=JudgeStats(),
        duration_s=0.0,
    )
    finding_ids = {rule["id"] for rule in to_sarif(from_finding)["runs"][0]["tool"]["driver"]["rules"]}
    assert "P.stale-alpha" in finding_ids
    assert "P.active-beta" not in finding_ids
    assert "P.active-quiet" not in finding_ids


def test_two_repos_do_not_leak_project_rules_into_sarif(tmp_path: Path) -> None:
    repo_a = tmp_path / "a"
    repo_b = tmp_path / "b"
    repo_a.mkdir()
    repo_b.mkdir()
    (repo_a / "app.py").write_text("ALPHA_TOKEN = 1\n", encoding="utf-8")
    (repo_b / "app.py").write_text("BETA_TOKEN = 1\n", encoding="utf-8")
    _write_rules(repo_a, [_pattern_rule("alpha-rule", "ALPHA_TOKEN", "alpha")])
    _write_rules(
        repo_b,
        [
            _pattern_rule("beta-rule", "BETA_TOKEN", "beta"),
            _pattern_rule("beta-quiet", "^NO_SUCH_TOKEN_ZZZ$", "quiet"),
        ],
    )
    sarif_a = tmp_path / "a.sarif"
    sarif_b = tmp_path / "b.sarif"
    sarif_a2 = tmp_path / "a2.sarif"
    assert _scan(repo_a, sarif_a) == 0
    rules_a = _sarif_ids(sarif_a)
    assert "P.alpha-rule" in rules_a
    assert "P.beta-rule" not in rules_a
    assert "D3.missing_auth" in rules_a

    assert _scan(repo_b, sarif_b) == 0
    rules_b = _sarif_ids(sarif_b)
    document_b = json.loads(sarif_b.read_text(encoding="utf-8"))
    result_ids = {item["ruleId"] for item in document_b["runs"][0]["results"]}
    assert "P.beta-rule" in rules_b
    assert "P.beta-quiet" in rules_b
    assert "P.beta-quiet" not in result_ids
    assert "P.alpha-rule" not in rules_b
    assert "P.alpha-rule" not in RULES
    assert "P.beta-rule" in RULES
    assert "D8.unbounded_retry" in rules_b

    assert _scan(repo_a, sarif_a2) == 0
    rules_a2 = _sarif_ids(sarif_a2)
    assert "P.alpha-rule" in rules_a2
    assert "P.beta-rule" not in rules_a2
    assert "P.beta-quiet" not in rules_a2
    assert "P.beta-rule" not in RULES
    assert "P.alpha-rule" in RULES
