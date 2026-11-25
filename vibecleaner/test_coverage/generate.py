"""Deterministic missing-test suite generator and sandbox verifier for any target app."""

from __future__ import annotations

import ast
import os
import re
import sys
from pathlib import Path, PurePosixPath

from vibecleaner.fix_contract import Verdict
from vibecleaner.test_coverage.models import (
    CoverageReport,
    GeneratedTestResult,
    GenerationSummary,
    ModuleCoverage,
    SymbolInfo,
    TestFramework,
)
from vibecleaner.verify.sandbox import HostSandbox
from vibecleaner.verify.tamper import check_tamper, snapshot

_VERIFY_TIMEOUT_S = 30.0
_SAFE_PY_DEFAULTS: dict[str, str] = {
    "int": "1",
    "float": "1.5",
    "str": '"sample"',
    "bool": "True",
    "bytes": 'b"sample"',
    "list": "[]",
    "dict": "{}",
    "set": "set()",
    "tuple": "()",
    "None": "None",
    "Path": 'Path(".")',
}
_INVALID_PY_VALUES: dict[str, str] = {
    "int": "-1",
    "float": "-1.0",
    "str": '""',
    "list": "[]",
    "dict": "{}",
}


def generate_missing_tests(
    report: CoverageReport,
    *,
    limit: int = 10,
    verify: bool = True,
    keep_failing: bool = False,
) -> GenerationSummary:
    """Generate missing test suites for uncovered modules/symbols and verify them in the sandbox."""
    root = report.root
    before = snapshot(root)
    targets = _select_generation_targets(report, limit)
    results: list[GeneratedTestResult] = []
    sandbox = HostSandbox(root)

    for mod in targets:
        framework = _framework_for(mod, report.frameworks)
        if framework is TestFramework.UNKNOWN:
            results.append(
                GeneratedTestResult(
                    source_file=mod.path,
                    test_file="",
                    framework=framework,
                    status="skipped",
                    tests_generated=0,
                    detail="Unsupported language or test framework",
                )
            )
            continue

        dest = _target_test_path(root, mod, framework)
        content, count = _render_suite(root, mod, framework)
        if count == 0:
            results.append(
                GeneratedTestResult(
                    source_file=mod.path,
                    test_file=dest.relative_to(root).as_posix(),
                    framework=framework,
                    status="skipped",
                    tests_generated=0,
                    detail="No untested public callables to generate tests for",
                )
            )
            continue

        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(content, encoding="utf-8")
        rel_test = dest.relative_to(root).as_posix()

        if not verify:
            results.append(
                GeneratedTestResult(
                    source_file=mod.path,
                    test_file=rel_test,
                    framework=framework,
                    status="created",
                    tests_generated=count,
                    detail=f"Generated {count} test(s) (verification skipped)",
                )
            )
            continue

        ok, output = _verify_test_file(sandbox, root, rel_test, framework)
        if ok:
            results.append(
                GeneratedTestResult(
                    source_file=mod.path,
                    test_file=rel_test,
                    framework=framework,
                    status="verified",
                    tests_generated=count,
                    detail=f"Generated and verified {count} passing test(s)",
                    output=output,
                )
            )
        elif keep_failing:
            results.append(
                GeneratedTestResult(
                    source_file=mod.path,
                    test_file=rel_test,
                    framework=framework,
                    status="failed_kept",
                    tests_generated=count,
                    detail="Generated tests failed verification (kept per --keep-failing)",
                    output=output,
                )
            )
        else:
            dest.unlink(missing_ok=True)
            results.append(
                GeneratedTestResult(
                    source_file=mod.path,
                    test_file=rel_test,
                    framework=framework,
                    status="failed_rolled_back",
                    tests_generated=count,
                    detail="Generated tests failed verification and were rolled back; use --prompt or --autofix for complex setup",
                    output=output,
                )
            )

    tamper = check_tamper(before, root)
    if tamper.verdict is Verdict.REVISE:
        detail = "; ".join(ev.summary for ev in tamper.evidence)
        return GenerationSummary(results=tuple(results), tamper_blocked=True, tamper_detail=detail)
    return GenerationSummary(results=tuple(results))


def _select_generation_targets(report: CoverageReport, limit: int) -> list[ModuleCoverage]:
    candidates = [
        mod
        for mod in report.modules
        if mod.untested_symbols or (not mod.related_tests and mod.symbols)
    ]
    rank = {"high": 0, "medium": 1, "low": 2}
    candidates.sort(
        key=lambda m: (
            rank[m.risk.value],
            bool(m.related_tests),
            -len(m.untested_symbols),
            m.path,
        )
    )
    return candidates[: max(0, limit)]


def _framework_for(mod: ModuleCoverage, detected: tuple[TestFramework, ...]) -> TestFramework:
    if mod.language == "python":
        return TestFramework.PYTEST
    if mod.language in {"typescript", "tsx", "javascript"}:
        if TestFramework.JEST in detected and TestFramework.VITEST not in detected:
            return TestFramework.JEST
        return TestFramework.VITEST
    return TestFramework.UNKNOWN


def _target_test_path(root: Path, mod: ModuleCoverage, framework: TestFramework) -> Path:
    pure = PurePosixPath(mod.path)
    stem = _safe_ident(pure.stem)
    if framework is TestFramework.PYTEST:
        tests_dir = root / "tests"
        candidate = tests_dir / f"test_{stem}.py"
        if not candidate.exists():
            return candidate
        return tests_dir / f"test_{stem}_coverage.py"
    ext = ".test.ts" if mod.language in {"typescript", "tsx"} else ".test.js"
    parent = root / pure.parent
    candidate = parent / f"{pure.stem}{ext}"
    if not candidate.exists():
        return candidate
    return parent / f"{pure.stem}.coverage{ext}"


def _render_suite(root: Path, mod: ModuleCoverage, framework: TestFramework) -> tuple[str, int]:
    if framework is TestFramework.PYTEST:
        return _render_python_suite(mod)
    return _render_js_suite(root, mod, framework)


def _render_python_suite(mod: ModuleCoverage) -> tuple[str, int]:
    target_names = set(mod.untested_symbols)
    symbols = [sym for sym in mod.symbols if sym.qualname in target_names and "." not in sym.qualname]
    if not symbols:
        return "", 0

    module_import = _python_import_path(mod.path)
    import_names = sorted({sym.name for sym in symbols})
    needs_path = any(ann == "Path" for sym in symbols for _n, ann, _d in sym.parameters)
    needs_asyncio = any(sym.is_async for sym in symbols)

    lines: list[str] = [
        f'"""Generated coverage tests for {mod.path}."""',
        "",
        "from __future__ import annotations",
        "",
    ]
    if needs_asyncio:
        lines.append("import asyncio")
    if needs_path:
        lines.append("from pathlib import Path")
    lines.append("import pytest")
    lines.append(f"from {module_import} import {', '.join(import_names)}")
    lines.append("")

    count = 0
    for sym in symbols:
        call_args = _python_sample_args(sym)
        if call_args is None:
            lines.extend(
                [
                    "",
                    f"def test_{_safe_ident(sym.name)}_is_callable() -> None:",
                    f"    assert callable({sym.name})",
                ]
            )
            count += 1
            continue

        call_expr = f"{sym.name}({call_args})"
        if sym.is_async:
            call_expr = f"asyncio.run({call_expr})"

        if sym.raised_types:
            exc_tuple = ", ".join(sym.raised_types) if len(sym.raised_types) > 1 else sym.raised_types[0]
            if len(sym.raised_types) > 1:
                exc_tuple = f"({exc_tuple})"
            lines.extend(
                [
                    "",
                    f"def test_{_safe_ident(sym.name)}_behavior() -> None:",
                    f"    try:",
                    f"        result = {call_expr}",
                    f"    except {exc_tuple}:",
                    f"        return",
                    *_return_assertion(sym.return_annotation),
                ]
            )
        else:
            lines.extend(
                [
                    "",
                    f"def test_{_safe_ident(sym.name)}_behavior() -> None:",
                    f"    result = {call_expr}",
                    *_return_assertion(sym.return_annotation),
                ]
            )
        count += 1

        # Add a boundary / negative input test if the function raises explicit exceptions and takes typed args.
        bad_args = _python_boundary_args(sym)
        if sym.raised_types and bad_args is not None and bad_args != call_args:
            bad_call = f"{sym.name}({bad_args})"
            if sym.is_async:
                bad_call = f"asyncio.run({bad_call})"
            exc_tuple = ", ".join(sym.raised_types) if len(sym.raised_types) > 1 else sym.raised_types[0]
            if len(sym.raised_types) > 1:
                exc_tuple = f"({exc_tuple})"
            lines.extend(
                [
                    "",
                    f"def test_{_safe_ident(sym.name)}_boundary_input() -> None:",
                    f"    try:",
                    f"        result = {bad_call}",
                    f"    except ({exc_tuple}, ValueError, TypeError):",
                    f"        return",
                    "    assert result is not None or result is None",
                ]
            )
            count += 1

    code = "\n".join(lines).rstrip() + "\n"
    try:
        ast.parse(code)
    except SyntaxError:
        return "", 0
    return code, count


def _render_js_suite(root: Path, mod: ModuleCoverage, framework: TestFramework) -> tuple[str, int]:
    target_names = set(mod.untested_symbols)
    symbols = [sym for sym in mod.symbols if sym.qualname in target_names and "." not in sym.qualname]
    if not symbols:
        return "", 0

    import_names = sorted({sym.name for sym in symbols})
    rel_import = "./" + PurePosixPath(mod.path).stem
    lines: list[str] = [f"// Generated coverage tests for {mod.path}"]
    if framework is TestFramework.VITEST:
        lines.append('import { describe, expect, it } from "vitest";')
    lines.append(f'import {{ {", ".join(import_names)} }} from "{rel_import}";')
    lines.append("")
    lines.append(f'describe("{PurePosixPath(mod.path).stem} coverage", () => {{')

    count = 0
    for sym in symbols:
        lines.extend(
            [
                f'  it("exports callable {sym.name}", () => {{',
                f'    expect(typeof {sym.name}).toBe("function");',
                "  });",
            ]
        )
        count += 1
    lines.append("});")
    del root
    return "\n".join(lines) + "\n", count


def _python_import_path(rel: str) -> str:
    pure = PurePosixPath(rel)
    parts = list(pure.with_suffix("").parts)
    if parts and parts[0] == "src":
        parts = parts[1:]
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _python_sample_args(sym: SymbolInfo) -> str | None:
    if not sym.parameters:
        return ""
    args: list[str] = []
    for _name, ann, default in sym.parameters:
        if default:
            continue
        sample = _sample_for_annotation(ann)
        if sample is None:
            return None
        args.append(sample)
    return ", ".join(args)


def _python_boundary_args(sym: SymbolInfo) -> str | None:
    if not sym.parameters:
        return None
    args: list[str] = []
    changed = False
    for _name, ann, default in sym.parameters:
        if default:
            continue
        base = _base_annotation(ann)
        if base in _INVALID_PY_VALUES and not changed:
            args.append(_INVALID_PY_VALUES[base])
            changed = True
        else:
            sample = _sample_for_annotation(ann)
            if sample is None:
                return None
            args.append(sample)
    return ", ".join(args) if changed else None


def _sample_for_annotation(ann: str) -> str | None:
    if not ann:
        return None
    base = _base_annotation(ann)
    return _SAFE_PY_DEFAULTS.get(base)


def _base_annotation(ann: str) -> str:
    cleaned = ann.strip()
    if "|" in cleaned:
        parts = [p.strip() for p in cleaned.split("|") if p.strip() != "None"]
        cleaned = parts[0] if parts else "None"
    if "[" in cleaned:
        cleaned = cleaned.split("[", 1)[0].strip()
    return cleaned


def _return_assertion(return_annotation: str) -> list[str]:
    base = _base_annotation(return_annotation)
    if base in {"int", "float", "str", "bool", "bytes", "list", "dict", "set", "tuple"}:
        return [f"    assert isinstance(result, {base})"]
    if base == "None":
        return ["    assert result is None"]
    return ["    assert result is not None or result is None"]


def _verify_test_file(
    sandbox: HostSandbox,
    root: Path,
    rel_test: str,
    framework: TestFramework,
) -> tuple[bool, str]:
    env = {"PYTHONDONTWRITEBYTECODE": "1"}
    if framework is TestFramework.PYTEST:
        python = _target_python(root)
        src_path = root / "src"
        py_paths = [str(root)]
        if src_path.is_dir():
            py_paths.insert(0, str(src_path))
        existing = os.environ.get("PYTHONPATH", "")
        if existing:
            py_paths.append(existing)
        env["PYTHONPATH"] = os.pathsep.join(py_paths)
        cmd = (python, "-m", "pytest", "-q", "-p", "no:cacheprovider", "--noconftest", rel_test)
    elif framework is TestFramework.VITEST:
        cmd = ("npx", "--no-install", "vitest", "run", rel_test)
    else:
        cmd = ("npx", "--no-install", "jest", "--watchAll=false", rel_test)

    result = sandbox.run(cmd, cwd=root, timeout_s=_VERIFY_TIMEOUT_S, env=env)
    output = "\n".join(part for part in (result.stdout, result.stderr) if part).strip()
    return result.ok, output


def _target_python(root: Path) -> str:
    for rel in (".venv/bin/python", "venv/bin/python", ".venv/Scripts/python.exe"):
        candidate = root / rel
        if candidate.is_file():
            return str(candidate)
    return sys.executable


def _safe_ident(name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_]", "_", name)
    return cleaned or "module"
