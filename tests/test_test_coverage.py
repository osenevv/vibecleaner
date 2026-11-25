"""Tests for auditing test coverage and generating missing test suites on target apps."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from vibecleaner.cli import main
from vibecleaner.models import RiskTier, Severity
from vibecleaner.test_coverage import (
    GapKind,
    TestFramework,
    audit_test_coverage,
    build_test_prompt,
    generate_missing_tests,
    render_coverage_markdown,
)


def _write_executable(path: Path, body: str) -> None:
    path.write_text(body, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


def test_audit_detects_missing_partial_error_and_lackluster_tests_python(tmp_path: Path) -> None:
    (tmp_path / "auth.py").write_text(
        "def verify_token(token: str) -> bool:\n"
        "    if not token:\n"
        "        raise ValueError('empty token')\n"
        "    return token.startswith('tok_')\n",
        encoding="utf-8",
    )
    (tmp_path / "calc.py").write_text(
        "def add(a: int, b: int) -> int:\n"
        "    return a + b\n\n"
        "def divide(a: int, b: int) -> float:\n"
        "    if b == 0:\n"
        "        raise ValueError('zero')\n"
        "    return a / b\n",
        encoding="utf-8",
    )
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    # Partial + lackluster test for calc.py: only calls add() with trivial assert, skips error path for divide().
    (tests_dir / "test_calc.py").write_text(
        "import pytest\n"
        "from calc import add\n\n"
        "def test_add_weak():\n"
        "    res = add(1, 2)\n"
        "    assert res is not None\n\n"
        "def test_no_assert():\n"
        "    add(1, 1)\n\n"
        "@pytest.mark.skip(reason='later')\n"
        "def test_skipped():\n"
        "    assert add(2, 3) == 5\n",
        encoding="utf-8",
    )

    report = audit_test_coverage(tmp_path)
    assert TestFramework.PYTEST in report.frameworks
    assert report.coverage_score < 60
    kinds = {gap.kind for gap in report.gaps}
    assert GapKind.MISSING_MODULE_TESTS in kinds
    assert GapKind.UNTESTED_SYMBOL in kinds
    assert GapKind.MISSING_ERROR_PATHS in kinds
    assert GapKind.LACKLUSTER_TEST in kinds

    auth_gap = next(g for g in report.gaps if g.file == "auth.py")
    assert auth_gap.risk is RiskTier.HIGH
    assert auth_gap.severity is Severity.CRITICAL

    reasons = {issue.reason for issue in report.quality_issues}
    assert "assertionless test" in reasons
    assert "tautological assertion" in reasons
    assert "skipped test" in reasons


def test_audit_clean_well_tested_python_app_has_no_gaps(tmp_path: Path) -> None:
    (tmp_path / "pricing.py").write_text(
        "def apply_discount(price: float, pct: float) -> float:\n"
        "    if pct < 0 or pct > 100:\n"
        "        raise ValueError('bad pct')\n"
        "    return round(price * (1 - pct / 100), 2)\n",
        encoding="utf-8",
    )
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_pricing.py").write_text(
        "import pytest\n"
        "from pricing import apply_discount\n\n"
        "def test_apply_discount_valid():\n"
        "    assert apply_discount(100.0, 20.0) == 80.0\n"
        "    assert apply_discount(50.0, 0.0) == 50.0\n\n"
        "def test_apply_discount_invalid():\n"
        "    with pytest.raises(ValueError):\n"
        "        apply_discount(100.0, -5.0)\n",
        encoding="utf-8",
    )

    report = audit_test_coverage(tmp_path, run_coverage=True)
    assert report.dynamic_coverage_ran is True
    assert report.coverage_score == 100
    assert report.gaps == ()
    assert report.quality_issues == ()
    assert report.modules[0].line_coverage_pct == 100.0


def test_audit_typescript_app_detects_missing_and_weak_vitest_tests(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        json.dumps({"devDependencies": {"vitest": "^2.0.0"}, "scripts": {"test": "vitest run"}}),
        encoding="utf-8",
    )
    src = tmp_path / "src"
    src.mkdir()
    (src / "format.ts").write_text(
        "export function formatPrice(cents: number): string {\n"
        "  if (cents < 0) { throw new Error('negative'); }\n"
        "  return `$${(cents / 100).toFixed(2)}`;\n"
        "}\n",
        encoding="utf-8",
    )
    (src / "slug.ts").write_text(
        "export const toSlug = (text: string): string => text.trim().toLowerCase().replace(/\\s+/g, '-');\n",
        encoding="utf-8",
    )
    (src / "slug.test.ts").write_text(
        'import { it, expect } from "vitest";\n'
        'import { toSlug } from "./slug";\n'
        'it("runs", () => { expect(toSlug("Hi")).toBeDefined(); });\n',
        encoding="utf-8",
    )

    report = audit_test_coverage(tmp_path)
    assert TestFramework.VITEST in report.frameworks
    assert any(g.file == "src/format.ts" and g.kind is GapKind.MISSING_MODULE_TESTS for g in report.gaps)
    assert any(i.file == "src/slug.test.ts" and i.reason == "weak matcher only" for i in report.quality_issues)


def test_generate_missing_tests_creates_and_verifies_python_suite(tmp_path: Path) -> None:
    (tmp_path / "math_utils.py").write_text(
        "def clamp(value: int, low: int = 0, high: int = 10) -> int:\n"
        "    if low > high:\n"
        "        raise ValueError('low > high')\n"
        "    return max(low, min(high, value))\n\n"
        "def is_even(n: int) -> bool:\n"
        "    return n % 2 == 0\n",
        encoding="utf-8",
    )
    before = audit_test_coverage(tmp_path)
    assert before.coverage_score == 0

    summary = generate_missing_tests(before, limit=5, verify=True)
    assert summary.tamper_blocked is False
    assert summary.verified_count == 1
    assert summary.results[0].status == "verified"
    generated_path = tmp_path / summary.results[0].test_file
    assert generated_path.is_file()

    after = audit_test_coverage(tmp_path, run_coverage=True)
    assert after.coverage_score > before.coverage_score
    assert after.tested_symbols == 2


def test_generate_missing_tests_does_not_overwrite_existing_test_file(tmp_path: Path) -> None:
    (tmp_path / "calc.py").write_text(
        "def add(a: int, b: int) -> int:\n    return a + b\n\n"
        "def sub(a: int, b: int) -> int:\n    return a - b\n",
        encoding="utf-8",
    )
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    existing = tests_dir / "test_calc.py"
    original = "from calc import add\n\ndef test_add():\n    assert add(1, 2) == 3\n"
    existing.write_text(original, encoding="utf-8")

    before = audit_test_coverage(tmp_path)
    summary = generate_missing_tests(before, limit=5, verify=True)
    assert existing.read_text(encoding="utf-8") == original
    assert summary.verified_count == 1
    assert summary.results[0].test_file == "tests/test_calc_coverage.py"


def test_generate_missing_tests_rolls_back_failing_suite_by_default(tmp_path: Path) -> None:
    (tmp_path / "broken_dep.py").write_text(
        "def explode(x: int) -> int:\n    raise RuntimeError('always fails')\n",
        encoding="utf-8",
    )
    # Remove explicit raise detection? Actually RuntimeError IS in raised_types, so let's make it fail via ZeroDivisionError
    # which is not explicitly raised with `raise`.
    (tmp_path / "broken_dep.py").write_text(
        "def explode(x: int) -> int:\n    return 1 // (x - x)\n",
        encoding="utf-8",
    )
    report = audit_test_coverage(tmp_path)
    summary = generate_missing_tests(report, limit=5, verify=True, keep_failing=False)
    assert summary.results[0].status == "failed_rolled_back"
    assert not (tmp_path / summary.results[0].test_file).exists()


def test_generate_typescript_suite_without_verify(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text('{"devDependencies": {"vitest": "^2.0.0"}}', encoding="utf-8")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "greet.ts").write_text(
        "export function greet(name: string): string { return 'hi ' + name; }\n",
        encoding="utf-8",
    )
    report = audit_test_coverage(tmp_path)
    summary = generate_missing_tests(report, limit=5, verify=False)
    assert summary.created_count == 1
    created = tmp_path / summary.results[0].test_file
    assert created.is_file()
    text = created.read_text(encoding="utf-8")
    assert 'from "vitest"' in text
    assert "greet" in text


def test_cli_tests_json_prompt_generate_and_min_score(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (tmp_path / "util.py").write_text(
        "def double(n: int) -> int:\n    return n * 2\n",
        encoding="utf-8",
    )
    # Below min-score -> exit 1
    rc_fail = main(["tests", str(tmp_path), "--min-score", "80", "--json"])
    assert rc_fail == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["coverage_score"] == 0
    assert payload["total_symbols"] == 1

    # Prompt output
    rc_prompt = main(["tests", str(tmp_path), "--prompt"])
    assert rc_prompt == 0
    prompt_out = capsys.readouterr().out
    assert "util.py" in prompt_out
    assert "instead of test doubles" in prompt_out

    # Generate + verify -> score rises to 100 -> passes min-score 80
    rc_gen = main(["tests", str(tmp_path), "--generate", "--min-score", "80"])
    assert rc_gen == 0
    assert (tmp_path / "VIBECLEANER_TESTS.md").is_file()
    assert (tmp_path / "tests" / "test_util.py").is_file()

    # Invalid flag bounds -> exit 2
    assert main(["tests", str(tmp_path), "--min-score", "150"]) == 2
    assert main(["tests", str(tmp_path), "--limit", "0"]) == 2


def test_cli_tests_autofix_improves_coverage_and_blocks_tamper(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    (tmp_path / "calc.py").write_text(
        "def triple(n: int) -> int:\n    return n * 3\n",
        encoding="utf-8",
    )
    bin_dir = tmp_path / "_bin"
    bin_dir.mkdir()
    good_agent = bin_dir / "fake-agent"
    _write_executable(
        good_agent,
        "#!/bin/sh\n"
        "mkdir -p tests\n"
        "cat > tests/test_calc.py <<'EOF'\n"
        "from calc import triple\n\n"
        "def test_triple():\n"
        "    assert triple(3) == 9\n"
        "EOF\n",
    )
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}")

    rc = main(["tests", str(tmp_path), "--autofix", "--agent", str(good_agent), "--min-score", "80", "--no-report"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "score 0 -> 100" in out

    # Now add a second untested module and run a tampering agent that deletes tests/test_calc.py.
    (tmp_path / "other.py").write_text("def quad(n: int) -> int:\n    return n * 4\n", encoding="utf-8")
    bad_agent = bin_dir / "bad-agent"
    _write_executable(bad_agent, "#!/bin/sh\nrm -f tests/test_calc.py\n")

    rc_tamper = main(["tests", str(tmp_path), "--autofix", "--agent", str(bad_agent), "--no-report"])
    assert rc_tamper == 2
    err = capsys.readouterr().err
    assert "tampering" in err.lower()


def test_render_markdown_and_prompt_helpers(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("def hello() -> str:\n    return 'hi'\n", encoding="utf-8")
    report = audit_test_coverage(tmp_path)
    md = render_coverage_markdown(report)
    assert "# Test Coverage & Quality Audit" in md
    assert "`a.py`" in md
    prompt = build_test_prompt(report)
    assert "a.py" in prompt


def test_audit_discovers_tests_even_when_vibecleanerignore_excludes_tests(tmp_path: Path) -> None:
    (tmp_path / ".vibecleanerignore").write_text("tests/\n", encoding="utf-8")
    (tmp_path / "svc.py").write_text("def ping() -> str:\n    return 'pong'\n", encoding="utf-8")
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_svc.py").write_text(
        "from svc import ping\n\ndef test_ping():\n    assert ping() == 'pong'\n",
        encoding="utf-8",
    )
    report = audit_test_coverage(tmp_path)
    assert report.test_files_count == 1
    assert report.tested_modules == 1
    assert report.coverage_score == 100
    assert report.gaps == ()
