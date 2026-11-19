"""Project rules: load, validate, pattern blanking, and import boundaries."""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path

import pytest

from vibecleaner.models import (
    PROJECT_RULE_PREFIX,
    RULES,
    Category,
    JudgeStats,
    Language,
    ScanResult,
    Severity,
    SourceFile,
    unregister_project_rules,
)
from vibecleaner.reporter import to_markdown, to_sarif
from vibecleaner.project_rules import (
    BoundaryRule,
    PatternRule,
    ProjectRulesError,
    _matches_forbid_path,
    add_boundary_rule,
    add_pattern_rule,
    apply_project_rules,
    load_project_rules,
    rule_hits_preview,
)

_USE_EFFECT = r"\buseEffect\s*\("


def _project_ids() -> set[str]:
    return {rule_id for rule_id in RULES if rule_id.startswith(PROJECT_RULE_PREFIX)}


def _write_rules(root: Path, payload: object) -> Path:
    path = root / ".vibecleaner" / "rules.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _source(path: str, text: str, language: Language | None = None) -> SourceFile:
    if language is None:
        language = {
            ".py": Language.PYTHON,
            ".ts": Language.TYPESCRIPT,
            ".tsx": Language.TSX,
            ".js": Language.JAVASCRIPT,
        }.get(Path(path).suffix, Language.OTHER)
    return SourceFile(path=path, abs_path=Path(path), language=language, text=text)


def _pattern_payload(**overrides: object) -> dict[str, object]:
    rule: dict[str, object] = {
        "id": "no-use-effect",
        "kind": "pattern",
        "pattern": _USE_EFFECT,
        "include": ["app/**"],
        "exclude": ["app/framework/**"],
        "severity": "high",
        "category": "slop",
        "message": "useEffect is reserved for framework internals",
    }
    rule.update(overrides)
    return rule


def test_load_missing_file_is_empty(tmp_path: Path) -> None:
    loaded = load_project_rules(tmp_path)
    assert loaded.rules == []
    assert loaded.path == tmp_path / ".vibecleaner" / "rules.json"
    assert not loaded.path.exists()


def test_load_rejects_invalid_json(tmp_path: Path) -> None:
    path = tmp_path / ".vibecleaner" / "rules.json"
    path.parent.mkdir(parents=True)
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(ProjectRulesError, match=r"rules\.json") as caught:
        load_project_rules(tmp_path)
    assert "invalid JSON" in str(caught.value)
    assert isinstance(caught.value, ValueError)


def test_load_rejects_duplicate_id(tmp_path: Path) -> None:
    rule = _pattern_payload(id="dup-rule")
    _write_rules(tmp_path, {"version": 1, "rules": [rule, dict(rule)]})
    with pytest.raises(ProjectRulesError, match=r"dup-rule") as caught:
        load_project_rules(tmp_path)
    assert "invalid id" in str(caught.value)
    assert "duplicate" in str(caught.value)
    assert f"{PROJECT_RULE_PREFIX}dup-rule" not in RULES


def test_load_rejects_bad_envelope(tmp_path: Path) -> None:
    _write_rules(tmp_path, {"version": 2, "rules": []})
    with pytest.raises(ProjectRulesError, match="invalid version"):
        load_project_rules(tmp_path)


def test_load_rejects_bad_regex(tmp_path: Path) -> None:
    _write_rules(tmp_path, {"version": 1, "rules": [_pattern_payload(id="bad-re", pattern="(")]})
    with pytest.raises(ProjectRulesError, match="bad-re") as caught:
        load_project_rules(tmp_path)
    assert "invalid pattern" in str(caught.value)
    assert f"{PROJECT_RULE_PREFIX}bad-re" not in RULES


@pytest.mark.parametrize(
    "rule",
    [
        _pattern_payload(id="Bad"),
        _pattern_payload(id="a"),
        _pattern_payload(kind="regex"),
        _pattern_payload(severity="huge"),
        _pattern_payload(category="style"),
        _pattern_payload(include=[]),
        _pattern_payload(include="app/**"),
        _pattern_payload(pattern=""),
        {"id": "ui-no-db", "kind": "import_boundary", "from": [], "forbid": ["os"], "severity": "high", "message": "no"},
        {"id": "ui-no-db", "kind": "import_boundary", "from": ["ui/**"], "forbid": [], "severity": "high", "message": "no"},
    ],
)
def test_load_rejects_schema(tmp_path: Path, rule: dict[str, object]) -> None:
    _write_rules(tmp_path, {"version": 1, "rules": [rule]})
    with pytest.raises(ProjectRulesError, match=r"rules\.json"):
        load_project_rules(tmp_path)


def test_pattern_skips_comments_strings_and_excluded_globs(tmp_path: Path) -> None:
    page = "\n".join(
        [
            "// useEffect(",
            'const label = "useEffect(";',
            "const tpl = `useEffect(`;",
            "/*",
            "useEffect(",
            "*/",
            "export function Page() {",
            "  return <div>{/* useEffect( */}</div>;",
            "}",
            "useEffect(() => {});",
            "",
        ]
    )
    hooks = "\n".join(
        [
            "# useEffect(",
            'x = "useEffect("',
            "y = '''",
            "useEffect(",
            "'''",
            'z = f"pre {useEffect()} post"',
            "def run():",
            "    useEffect()",
            "",
        ]
    )
    files = [
        _source("app/page.tsx", page),
        _source("app/hooks.py", hooks),
        _source("app/framework/runtime.tsx", "useEffect(() => {});\n"),
        _source("app/framework/deep/io.tsx", "useEffect(() => {});\n"),
        _source("components/Widget.tsx", "useEffect(() => {});\n"),
    ]
    _write_rules(tmp_path, {"version": 1, "rules": [_pattern_payload()]})
    findings = apply_project_rules(load_project_rules(tmp_path), files)
    hits = {(item.file, item.line) for item in findings}
    assert hits == {("app/page.tsx", 10), ("app/hooks.py", 6), ("app/hooks.py", 8)}
    page_hit = next(item for item in findings if item.file == "app/page.tsx")
    assert page_hit.rule_id == "P.no-use-effect"
    assert "useEffect(() => {})" in (page_hit.snippet or "")
    assert page_hit.message == "useEffect is reserved for framework internals"


def test_match_comments_sees_comment_text(tmp_path: Path) -> None:
    _write_rules(
        tmp_path,
        {
            "version": 1,
            "rules": [
                _pattern_payload(
                    id="comments-too",
                    exclude=[],
                    message="also comments",
                    match_comments=True,
                )
            ],
        },
    )
    loaded = load_project_rules(tmp_path)
    assert loaded.rules[0].match_comments is True
    findings = apply_project_rules(
        loaded,
        [_source("app/page.tsx", "// useEffect(\nconst ok = 1;\n")],
    )
    assert [(item.file, item.line) for item in findings] == [("app/page.tsx", 1)]


def test_import_boundaries_flag_alias_package_and_python(tmp_path: Path) -> None:
    path = add_boundary_rule(
        tmp_path,
        "ui-no-db",
        ["app/components/**", "ui/**"],
        ["lib/db/**", "@prisma/client", "server/**"],
        "UI components must not import the database layer",
        learned_from="card imported the database",
    )
    saved = json.loads(path.read_text(encoding="utf-8"))
    assert saved["version"] == 1
    assert saved["rules"][0]["kind"] == "import_boundary"
    assert saved["rules"][0]["from"] == ["app/components/**", "ui/**"]
    assert saved["rules"][0]["added"] == date.today().isoformat()

    card = "\n".join(
        [
            "import { db } from '@/lib/db'",
            "import type { Db } from '@/lib/db'",
            "import { PrismaClient } from '@prisma/client'",
            "import { edge } from '@prisma/client/edge'",
            "import runtime from '@prisma/client-runtime'",
            "import { helper } from './helper'",
            "export function Card() { return null }",
            "",
        ]
    )
    views = "\n".join(
        [
            "import os",
            "from pathlib import Path",
            "from server.db import session",
            "",
            "def view():",
            "    return session",
            "",
        ]
    )
    panel = "from ..server.db import session\n"
    files = [
        _source("app/components/Card.tsx", card),
        _source("ui/views.py", views),
        _source("ui/panel.py", panel),
        _source("services/query.ts", "import { db } from '@/lib/db'\n"),
    ]
    loaded = load_project_rules(tmp_path)
    findings = apply_project_rules(loaded, files)
    by_file: dict[str, list[str]] = {}
    for finding in findings:
        by_file.setdefault(finding.file, []).append(finding.message)

    assert by_file["app/components/Card.tsx"] == [
        "UI components must not import the database layer (imports @/lib/db)",
        "UI components must not import the database layer (imports @/lib/db)",
        "UI components must not import the database layer (imports @prisma/client)",
        "UI components must not import the database layer (imports @prisma/client/edge)",
    ]
    assert "services/query.ts" not in by_file
    assert by_file["ui/views.py"] == [
        "UI components must not import the database layer (imports server.db)"
    ]
    assert by_file["ui/panel.py"] == [
        "UI components must not import the database layer (imports ..server.db)"
    ]
    assert findings[0].snippet == "import { db } from '@/lib/db'"
    assert all(item.rule_id == "P.ui-no-db" for item in findings)


def test_add_pattern_rule_appends_and_rejects_without_touching_file(tmp_path: Path) -> None:
    with pytest.raises(ProjectRulesError):
        add_pattern_rule(tmp_path, "bad-re", "(", "broken")
    assert not (tmp_path / ".vibecleaner").exists()

    broken = tmp_path / "broken"
    broken.mkdir()
    target = broken / ".vibecleaner" / "rules.json"
    target.parent.mkdir(parents=True)
    target.write_text("{", encoding="utf-8")
    before_broken = target.read_bytes()
    with pytest.raises(ProjectRulesError, match="invalid JSON"):
        add_pattern_rule(broken, "no-use-effect", _USE_EFFECT, "no", include=["app/**"])
    assert target.read_bytes() == before_broken

    path = add_pattern_rule(
        tmp_path,
        "no-use-effect",
        _USE_EFFECT,
        "useEffect is reserved for framework internals",
        include=["app/**"],
        exclude=["app/framework/**"],
        severity="high",
        category="slop",
        remediation="use a server component",
        learned_from="pages were calling useEffect for data",
    )
    assert path == tmp_path / ".vibecleaner" / "rules.json"
    first = path.read_bytes()
    assert first.endswith(b"\n")
    payload = json.loads(first)
    assert list(payload) == ["version", "rules"]
    rule = payload["rules"][0]
    assert list(rule) == [
        "id",
        "kind",
        "pattern",
        "include",
        "exclude",
        "severity",
        "category",
        "message",
        "remediation",
        "learned_from",
        "added",
    ]
    assert rule["added"] == date.today().isoformat()
    assert rule["learned_from"] == "pages were calling useEffect for data"

    add_pattern_rule(
        tmp_path,
        "no-console",
        r"\bconsole\.log\s*\(",
        "no console",
        include=["app/**"],
        severity="low",
    )
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert [item["id"] for item in payload["rules"]] == ["no-use-effect", "no-console"]

    before = path.read_bytes()
    with pytest.raises(ProjectRulesError, match="no-use-effect"):
        add_pattern_rule(tmp_path, "no-use-effect", r"\bfoo\s*\(", "duplicate", include=["app/**"])
    assert path.read_bytes() == before
    with pytest.raises(ProjectRulesError, match="invalid pattern"):
        add_pattern_rule(tmp_path, "still-bad", "(", "nope", include=["app/**"])
    assert path.read_bytes() == before
    with pytest.raises(ProjectRulesError, match="invalid severity"):
        add_boundary_rule(tmp_path, "ui-no-db", ["ui/**"], ["server/**"], "no", severity="nope")
    assert path.read_bytes() == before


def test_registered_spec_and_finding_severity(tmp_path: Path) -> None:
    message = "useEffect is reserved for framework internals"
    add_pattern_rule(
        tmp_path,
        "no-use-effect",
        _USE_EFFECT,
        message,
        include=["app/**"],
        remediation="use a server component or the data hook",
    )
    loaded = load_project_rules(tmp_path)
    load_project_rules(tmp_path)
    spec = RULES["P.no-use-effect"]
    assert spec.rule_id == "P.no-use-effect"
    assert spec.detector == "P"
    assert spec.layer == 1
    assert spec.category == Category.SLOP
    assert spec.severity == Severity.HIGH
    assert spec.title == message[:80]
    assert spec.remediation == "use a server component or the data hook"

    findings = apply_project_rules(
        loaded,
        [_source("app/page.tsx", "export const Page = () => {\n  useEffect(() => {});\n};\n")],
    )
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert findings[0].category == Category.SLOP
    assert findings[0].line == 2


def test_rule_hits_preview_runs_one_rule(tmp_path: Path) -> None:
    page = tmp_path / "app" / "page.tsx"
    page.parent.mkdir(parents=True)
    page.write_text("// useEffect(\nuseEffect(() => {});\n", encoding="utf-8")
    other = tmp_path / "lib" / "note.ts"
    other.parent.mkdir(parents=True)
    other.write_text("useEffect(() => {});\n", encoding="utf-8")
    rule = PatternRule(
        id="preview-effect",
        pattern=_USE_EFFECT,
        include=["app/**"],
        message="preview",
        severity="medium",
        category="slop",
    )
    before = _project_ids()
    findings = rule_hits_preview(tmp_path, rule)
    assert [(item.file, item.line) for item in findings] == [("app/page.tsx", 2)]
    assert findings[0].message == "preview"
    assert rule.severity == "medium"
    assert "P.preview-effect" not in RULES
    assert _project_ids() == before

    bad = PatternRule(id="bad-re", pattern="(", include=["app/**"], message="no")
    with pytest.raises(ProjectRulesError, match="invalid pattern"):
        rule_hits_preview(tmp_path, bad)
    assert "P.bad-re" not in RULES
    assert _project_ids() == before


def test_boundary_preview_on_walked_repo(tmp_path: Path) -> None:
    card = tmp_path / "app" / "components" / "Card.tsx"
    card.parent.mkdir(parents=True)
    card.write_text("import { db } from '@/lib/db'\nexport function Card() { return null }\n", encoding="utf-8")
    rule = BoundaryRule(
        id="ui-no-db",
        from_globs=["app/components/**"],
        forbid=["lib/db/**", "@prisma/client"],
        message="no db",
    )
    before = _project_ids()
    findings = rule_hits_preview(tmp_path, rule)
    assert len(findings) == 1
    assert findings[0].file == "app/components/Card.tsx"
    assert findings[0].message == "no db (imports @/lib/db)"
    assert _project_ids() == before


def test_preview_does_not_overwrite_a_saved_rule(tmp_path: Path) -> None:
    add_pattern_rule(tmp_path, "same-id", "SAVED", "saved message", severity="high")
    saved = RULES["P.same-id"]
    rule = PatternRule(
        id="same-id",
        pattern="PREVIEW",
        include=["**"],
        message="preview message",
        severity="low",
    )
    page = tmp_path / "app.py"
    page.write_text("PREVIEW = 1\n", encoding="utf-8")
    findings = rule_hits_preview(tmp_path, rule)
    assert [(item.file, item.line) for item in findings] == [("app.py", 1)]
    assert RULES["P.same-id"] is saved
    assert RULES["P.same-id"].title == "saved message"
    assert RULES["P.same-id"].severity == Severity.HIGH


def test_load_replaces_previously_registered_project_rules(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    add_pattern_rule(first, "from-first", "ALPHA", "first rule")
    assert "P.from-first" in RULES
    add_pattern_rule(second, "from-second", "BETA", "second rule")
    assert "P.from-second" in RULES
    assert "P.from-first" not in RULES
    assert RULES["P.from-second"].title == "second rule"

    empty = tmp_path / "empty"
    _write_rules(empty, {"version": 1, "rules": []})
    load_project_rules(empty)
    assert "P.from-second" not in RULES

    load_project_rules(second)
    assert "P.from-second" in RULES
    missing = tmp_path / "missing"
    missing.mkdir()
    load_project_rules(missing)
    assert "P.from-second" not in RULES


def test_failed_load_keeps_previously_registered_rules(tmp_path: Path) -> None:
    good = tmp_path / "good"
    add_pattern_rule(good, "kept-rule", "KEEP", "kept")
    bad = tmp_path / "bad"
    _write_rules(bad, {"version": 1, "rules": [_pattern_payload(id="bad-lane", lane="nope")]})
    with pytest.raises(ProjectRulesError, match="invalid lane"):
        load_project_rules(bad)
    assert "P.kept-rule" in RULES
    assert "P.bad-lane" not in RULES
    assert "D1.hardcoded_secret" in RULES


def test_unregister_project_rules_refuses_builtin_ids() -> None:
    with pytest.raises(ValueError, match="P."):
        unregister_project_rules(["D1.hardcoded_secret"])
    assert "D1.hardcoded_secret" in RULES


def test_pattern_lane_defaults_to_absent_and_rejects_unknown(tmp_path: Path) -> None:
    _write_rules(tmp_path, {"version": 1, "rules": [_pattern_payload(pattern=r"a{2}")]})
    loaded = load_project_rules(tmp_path)
    assert isinstance(loaded.rules[0], PatternRule)
    assert loaded.rules[0].lane is None
    assert loaded.rules[0].pattern == r"a{2}"

    path = add_pattern_rule(
        tmp_path,
        "lane-rule",
        "TOKEN",
        "use a real type",
        include=["**"],
        lane="weak-types",
    )
    saved = json.loads(path.read_text(encoding="utf-8"))
    by_id = {item["id"]: item for item in saved["rules"]}
    assert by_id["lane-rule"]["lane"] == "weak-types"
    assert "lane" not in by_id["no-use-effect"]
    assert load_project_rules(tmp_path).rules[1].lane == "weak-types"

    before = path.read_bytes()
    with pytest.raises(ProjectRulesError, match="invalid lane"):
        add_pattern_rule(tmp_path, "bad-lane", "TOKEN", "no", lane="nope")
    assert path.read_bytes() == before


@pytest.mark.parametrize(
    ("field_name", "rule"),
    [
        ("include", _pattern_payload(id="brace-include", include=["**/*.{ts,tsx}"])),
        ("exclude", _pattern_payload(id="brace-exclude", exclude=["**/*.{ts,tsx}"])),
        (
            "from",
            {
                "id": "brace-from",
                "kind": "import_boundary",
                "from": ["**/*.{ts,tsx}"],
                "forbid": ["os"],
                "severity": "high",
                "message": "no",
            },
        ),
        (
            "forbid",
            {
                "id": "brace-forbid",
                "kind": "import_boundary",
                "from": ["ui/**"],
                "forbid": ["lib/*.{ts,js}"],
                "severity": "high",
                "message": "no",
            },
        ),
        ("include", _pattern_payload(id="lone-brace", include=["}"])),
    ],
)
def test_brace_globs_are_rejected(tmp_path: Path, field_name: str, rule: dict[str, object]) -> None:
    _write_rules(tmp_path, {"version": 1, "rules": [rule]})
    with pytest.raises(ProjectRulesError, match="list each glob separately") as caught:
        load_project_rules(tmp_path)
    message = str(caught.value)
    assert f"invalid {field_name}" in message
    assert "'{'" in message or "'}'" in message
    assert f"P.{rule['id']}" not in RULES


@pytest.mark.parametrize("forbid", ["lib/db", "lib.db"])
def test_nonglob_forbid_matches_resolved_path(tmp_path: Path, forbid: str) -> None:
    _write_rules(
        tmp_path,
        {
            "version": 1,
            "rules": [
                {
                    "id": "ui-no-db",
                    "kind": "import_boundary",
                    "from": ["app/components/**", "ui/**"],
                    "forbid": [forbid],
                    "severity": "high",
                    "message": "no db",
                }
            ],
        },
    )
    files = [
        _source(
            "app/components/Card.tsx",
            "import { db } from '@/lib/db'\nexport function Card() { return null }\n",
        ),
        _source("ui/panel.py", "from ..lib.db import connect\n"),
        _source("app/components/Other.tsx", "import { db } from '@/lib/database'\n"),
        _source("app/components/Extra.tsx", "import { db } from '@/lib/db_extra'\n"),
        _source("services/query.ts", "import { db } from '@/lib/db'\n"),
    ]
    findings = apply_project_rules(load_project_rules(tmp_path), files)
    hits = {(item.file, item.message) for item in findings}
    assert hits == {
        ("app/components/Card.tsx", "no db (imports @/lib/db)"),
        ("ui/panel.py", "no db (imports ..lib.db)"),
    }


def test_nonglob_package_specifier_still_matches(tmp_path: Path) -> None:
    _write_rules(
        tmp_path,
        {
            "version": 1,
            "rules": [
                {
                    "id": "no-prisma",
                    "kind": "import_boundary",
                    "from": ["app/**"],
                    "forbid": ["@prisma/client"],
                    "severity": "high",
                    "message": "no prisma",
                }
            ],
        },
    )
    files = [
        _source("app/db.ts", "import { PrismaClient } from '@prisma/client'\n"),
        _source("app/edge.ts", "import { edge } from '@prisma/client/edge'\n"),
        _source("app/runtime.ts", "import runtime from '@prisma/client-runtime'\n"),
    ]
    findings = apply_project_rules(load_project_rules(tmp_path), files)
    assert [(item.file, item.message) for item in findings] == [
        ("app/db.ts", "no prisma (imports @prisma/client)"),
        ("app/edge.ts", "no prisma (imports @prisma/client/edge)"),
    ]


def test_src_alias_and_dotted_forbid_prefixes() -> None:
    assert _matches_forbid_path(["src/lib/db.ts"], "lib/db")
    assert _matches_forbid_path(["lib/db.ts"], "src/lib/db")
    assert _matches_forbid_path(["lib/db.py", "lib/db/__init__.py"], "lib.db")
    assert _matches_forbid_path(["lib/db/index.ts"], "lib/db")
    assert _matches_forbid_path(["src/lib/db/index.ts"], "lib.db")
    assert not _matches_forbid_path(["lib/database.ts"], "lib/db")
    assert not _matches_forbid_path(["lib/db_extra.ts"], "lib/db")
    assert not _matches_forbid_path(["lib/dbx.py"], "lib.db")
    assert not _matches_forbid_path(["src/lib/db.ts"], "@prisma/client")


def test_preview_findings_carry_self_contained_spec(tmp_path: Path) -> None:
    page = tmp_path / "app" / "page.tsx"
    page.parent.mkdir(parents=True)
    page.write_text("useEffect(() => {});\n", encoding="utf-8")
    card = tmp_path / "app" / "components" / "Card.tsx"
    card.parent.mkdir(parents=True)
    card.write_text("import { db } from '@/lib/db'\n", encoding="utf-8")

    pattern_rule = PatternRule(
        id="preview-self-contained",
        pattern=_USE_EFFECT,
        include=["app/**"],
        message="no useEffect",
        severity="medium",
        category="slop",
        remediation="remove useEffect",
    )
    boundary_rule = BoundaryRule(
        id="preview-boundary-self-contained",
        from_globs=["app/components/**"],
        forbid=["lib/db/**"],
        message="no db",
        severity="high",
        category="security",
        remediation="move db access out",
    )

    p_findings = rule_hits_preview(tmp_path, pattern_rule)
    b_findings = rule_hits_preview(tmp_path, boundary_rule)
    assert f"{PROJECT_RULE_PREFIX}{pattern_rule.id}" not in RULES
    assert f"{PROJECT_RULE_PREFIX}{boundary_rule.id}" not in RULES

    assert len(p_findings) == 1
    assert p_findings[0].severity == Severity.MEDIUM
    assert p_findings[0].category == Category.SLOP
    assert p_findings[0].spec.remediation == "remove useEffect"

    assert len(b_findings) == 1
    assert b_findings[0].severity == Severity.HIGH
    assert b_findings[0].category == Category.SECURITY
    assert b_findings[0].spec.remediation == "move db access out"


def test_historical_scan_result_renders_after_rules_replaced(tmp_path: Path) -> None:
    repo_a = tmp_path / "repo_a"
    repo_b = tmp_path / "repo_b"
    add_pattern_rule(
        repo_a,
        "repo-a-only",
        r"\bLEGACY_CALL\b",
        "avoid legacy call",
        severity="high",
        category="slop",
        remediation="use modern_call instead",
    )
    findings = apply_project_rules(
        load_project_rules(repo_a),
        [_source("app/main.py", "LEGACY_CALL()\n")],
    )
    result = ScanResult(
        root=repo_a,
        findings=findings,
        files_scanned=1,
        judge=JudgeStats(mode="offline"),
        duration_s=0.1,
    )

    add_pattern_rule(repo_b, "repo-b-only", r"\bOTHER\b", "other rule")
    load_project_rules(repo_b)
    assert "P.repo-a-only" not in RULES

    md = to_markdown(result)
    assert "P.repo-a-only" in md
    assert "use modern_call instead" in md

    sarif = to_sarif(result)
    runs = sarif["runs"]
    assert isinstance(runs, list) and len(runs) == 1
    rule_ids = {rule["id"] for rule in runs[0]["tool"]["driver"]["rules"]}
    assert "P.repo-a-only" in rule_ids
    assert runs[0]["results"][0]["ruleId"] == "P.repo-a-only"
