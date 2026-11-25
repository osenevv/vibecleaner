"""Audit test coverage and test quality for any Python or JavaScript/TypeScript app."""

from __future__ import annotations

import ast
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path, PurePosixPath

from vibecleaner.collector import _is_test_unit_path, collect
from vibecleaner.models import Language, RiskTier, Severity, SourceFile
from vibecleaner.risk import classify_file
from vibecleaner.test_coverage.models import (
    CoverageGap,
    CoverageReport,
    GapKind,
    ModuleCoverage,
    SymbolInfo,
    TestFramework,
    TestQualityIssue,
)
from vibecleaner.ts_parse import node_text, parse_root

_CODE_LANGUAGES = frozenset({Language.PYTHON, Language.TYPESCRIPT, Language.TSX, Language.JAVASCRIPT})
_ROUTE_DECORATORS = frozenset({"get", "post", "put", "patch", "delete", "route", "api_route"})
_HTTP_EXPORTS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"})
_PY_ASSERT_RE = re.compile(r"\bassert\b|pytest\.raises|assertRaises|assertEqual|assertTrue|assertFalse")
_JS_ASSERT_RE = re.compile(r"\bexpect\s*\(|assert\.\w+\s*\(")
_PY_WEAK_ASSERT_RE = re.compile(r"^\s*assert\s+(?:True|1|not\s+None|\w+\s+is\s+not\s+None)\s*$", re.MULTILINE)
_JS_WEAK_MATCHER_RE = re.compile(r"\.(?:toBeDefined|toBeTruthy|toBeFalsy|toBeNull|toBeUndefined)\s*\(\s*\)")
_JS_STRONG_MATCHER_RE = re.compile(
    r"\.(?:toBe|toEqual|toStrictEqual|toContain|toMatch|toThrow|toHaveBeenCalled|toHaveLength|rejects)\b"
)
_SKIP_MARKERS_PY = ("pytest.mark.skip", "pytest.mark.xfail", "unittest.skip")
_SKIP_MARKERS_JS = ("it.skip(", "test.skip(", "describe.skip(", "xit(", "xtest(", "xdescribe(", ".only(")
_ERROR_TEST_MARKERS = (
    "pytest.raises",
    "assertRaises",
    "toThrow",
    "rejects",
    "ValueError",
    "TypeError",
    "KeyError",
    "RuntimeError",
    "status_code",
    "400",
    "401",
    "403",
    "404",
    "422",
    "invalid",
    "error",
)
_MOCK_MARKERS = (
    "unittest.mock",
    "MagicMock",
    "patch(",
    "jest.mock(",
    "vi.mock(",
)
_JS_THROW_RE = re.compile(r"\bthrow\s+new\s+(\w+)|\bthrow\s+|status\(\s*(?:4\d\d|5\d\d)\s*\)")
_DYNAMIC_COVERAGE_TIMEOUT_S = 60
_TEST_WALK_SKIP = frozenset(
    {
        ".git",
        ".hg",
        ".venv",
        "venv",
        "env",
        "node_modules",
        "__pycache__",
        ".vibecleaner",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        ".next",
        "dist",
        "build",
        "coverage",
        "benchmarks",
    }
)
_SUFFIX_TO_LANG: dict[str, Language] = {
    ".py": Language.PYTHON,
    ".ts": Language.TYPESCRIPT,
    ".tsx": Language.TSX,
    ".js": Language.JAVASCRIPT,
    ".jsx": Language.TSX,
    ".mjs": Language.JAVASCRIPT,
    ".cjs": Language.JAVASCRIPT,
}


def detect_frameworks(root: Path, files: list[SourceFile]) -> tuple[TestFramework, ...]:
    """Detect the test frameworks used or appropriate for ``root``."""
    found: list[TestFramework] = []
    has_py = any(sf.language is Language.PYTHON for sf in files)
    has_js = any(sf.language in {Language.TYPESCRIPT, Language.TSX, Language.JAVASCRIPT} for sf in files)
    if has_py or (root / "pyproject.toml").is_file() or (root / "pytest.ini").is_file():
        found.append(TestFramework.PYTEST)
    pkg_path = root / "package.json"
    if pkg_path.is_file():
        try:
            pkg = json.loads(pkg_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            pkg = {}
        deps: dict[str, object] = {}
        if isinstance(pkg, dict):
            for key in ("dependencies", "devDependencies"):
                block = pkg.get(key)
                if isinstance(block, dict):
                    deps.update(block)
            scripts = pkg.get("scripts")
            test_script = scripts.get("test", "") if isinstance(scripts, dict) else ""
        else:
            test_script = ""
        if "vitest" in deps or (isinstance(test_script, str) and "vitest" in test_script):
            found.append(TestFramework.VITEST)
        elif "jest" in deps or (isinstance(test_script, str) and "jest" in test_script):
            found.append(TestFramework.JEST)
        elif has_js:
            found.append(TestFramework.VITEST)
    elif has_js:
        found.append(TestFramework.VITEST)
    return tuple(found) if found else (TestFramework.UNKNOWN,)


def audit_test_coverage(
    root: Path,
    *,
    diff_base: str | None = None,
    run_coverage: bool = False,
) -> CoverageReport:
    """Audit test coverage and test quality for any target repository."""
    root = Path(root).expanduser().resolve()
    ctx = collect(root, diff_base=diff_base)
    all_code = [sf for sf in ctx.files if sf.language in _CODE_LANGUAGES]
    prod_files = [sf for sf in all_code if not _is_test_unit_path(sf.path) and not _is_config_or_init_stub(sf)]
    test_files = _discover_test_files(root)

    frameworks = detect_frameworks(root, all_code + test_files)
    dynamic_map: dict[str, tuple[float, tuple[int, ...]]] = {}
    dynamic_ran = False
    dynamic_note: str | None = None
    if run_coverage and TestFramework.PYTEST in frameworks:
        py_map, py_ran, py_note = _run_python_line_coverage(root)
        dynamic_map.update(py_map)
        dynamic_ran = dynamic_ran or py_ran
        dynamic_note = py_note
    if run_coverage and (TestFramework.VITEST in frameworks or TestFramework.JEST in frameworks):
        js_map, js_ran, js_note = _read_js_coverage_summary(root)
        dynamic_map.update(js_map)
        dynamic_ran = dynamic_ran or js_ran
        if js_note and dynamic_note is None:
            dynamic_note = js_note

    quality_issues = _audit_test_quality(test_files)
    modules: list[ModuleCoverage] = []
    gaps: list[CoverageGap] = []

    for sf in sorted(prod_files, key=lambda item: item.path):
        risk = classify_file(sf.path, sf.text)
        symbols = extract_symbols(sf)
        related = _find_related_tests(sf, symbols, test_files)
        related_text = "\n".join(test.text for test in related)

        tested: list[str] = []
        untested: list[str] = []
        for sym in symbols:
            if _symbol_referenced(sym, related_text):
                tested.append(sym.qualname)
            else:
                untested.append(sym.qualname)

        needs_err = any(sym.raises_errors or sym.is_route for sym in symbols)
        has_err = bool(related) and any(marker in related_text for marker in _ERROR_TEST_MARKERS)

        line_pct: float | None = None
        missed: tuple[int, ...] = ()
        if sf.path in dynamic_map:
            line_pct, missed = dynamic_map[sf.path]

        mod = ModuleCoverage(
            path=sf.path,
            language=sf.language.value,
            risk=risk,
            symbols=symbols,
            tested_symbols=tuple(tested),
            untested_symbols=tuple(untested),
            related_tests=tuple(t.path for t in related),
            has_error_path_tests=has_err,
            needs_error_path_tests=needs_err,
            line_coverage_pct=line_pct,
            missed_lines=missed,
        )
        modules.append(mod)
        gaps.extend(_gaps_for_module(mod))

    for issue in quality_issues:
        gaps.append(
            CoverageGap(
                kind=GapKind.LACKLUSTER_TEST,
                severity=issue.severity,
                file=issue.file,
                line=issue.line,
                symbol=None,
                message=f"{issue.reason}: {issue.detail}",
                remediation="Replace weak, skipped, or mock-heavy tests with real behavioral assertions.",
                risk=RiskTier.MEDIUM,
            )
        )

    gaps.sort(key=lambda g: (-g.severity.rank, _risk_rank(g.risk), g.file, g.line))
    score = _compute_score(modules, quality_issues)
    return CoverageReport(
        root=root,
        frameworks=frameworks,
        coverage_score=score,
        modules=tuple(modules),
        gaps=tuple(gaps),
        quality_issues=tuple(quality_issues),
        test_files_count=len(test_files),
        dynamic_coverage_ran=dynamic_ran,
        dynamic_coverage_note=dynamic_note,
        diff_base=diff_base,
    )


def extract_symbols(source: SourceFile) -> tuple[SymbolInfo, ...]:
    """Extract public functions, methods, and exported callables from a source file."""
    if source.language is Language.PYTHON:
        return _python_symbols(source.text)
    if source.language in {Language.TYPESCRIPT, Language.TSX, Language.JAVASCRIPT}:
        return _script_symbols(source)
    return ()


def _python_symbols(text: str) -> tuple[SymbolInfo, ...]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return ()
    found: list[SymbolInfo] = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if not node.name.startswith("_"):
                found.append(_py_func_info(node, None))
        elif isinstance(node, ast.ClassDef) and not node.name.startswith("_"):
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and not item.name.startswith("_"):
                    found.append(_py_func_info(item, node.name))
    return tuple(found)


def _py_func_info(node: ast.FunctionDef | ast.AsyncFunctionDef, class_name: str | None) -> SymbolInfo:
    qualname = f"{class_name}.{node.name}" if class_name else node.name
    is_route = any(_decorator_leaf(dec) in _ROUTE_DECORATORS for dec in node.decorator_list)
    raised = _py_raised_types(node)
    params = _py_params(node)
    ret = ast.unparse(node.returns) if node.returns is not None else ""
    prefix = "async def" if isinstance(node, ast.AsyncFunctionDef) else "def"
    sig = f"{prefix} {node.name}({ast.unparse(node.args)})" + (f" -> {ret}" if ret else "")
    return SymbolInfo(
        name=node.name,
        qualname=qualname,
        line=node.lineno,
        end_line=node.end_lineno or node.lineno,
        signature=sig,
        is_async=isinstance(node, ast.AsyncFunctionDef),
        is_route=is_route,
        raises_errors=bool(raised),
        parameters=params,
        return_annotation=ret,
        raised_types=raised,
    )


def _py_params(node: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[tuple[str, str, str], ...]:
    args = list(node.args.posonlyargs) + list(node.args.args)
    defaults = [None] * (len(args) - len(node.args.defaults)) + list(node.args.defaults)
    out: list[tuple[str, str, str]] = []
    for arg, default in zip(args, defaults):
        if arg.arg in {"self", "cls"}:
            continue
        ann = ast.unparse(arg.annotation) if arg.annotation is not None else ""
        dflt = ast.unparse(default) if default is not None else ""
        out.append((arg.arg, ann, dflt))
    for arg, default in zip(node.args.kwonlyargs, node.args.kw_defaults):
        ann = ast.unparse(arg.annotation) if arg.annotation is not None else ""
        dflt = ast.unparse(default) if default is not None else ""
        out.append((arg.arg, ann, dflt))
    return tuple(out)


def _py_raised_types(node: ast.AST) -> tuple[str, ...]:
    names: list[str] = []
    for child in ast.walk(node):
        if not isinstance(child, ast.Raise) or child.exc is None:
            continue
        exc = child.exc.func if isinstance(child.exc, ast.Call) else child.exc
        if isinstance(exc, ast.Name) and exc.id not in names:
            names.append(exc.id)
        elif isinstance(exc, ast.Attribute) and exc.attr not in names:
            names.append(exc.attr)
    return tuple(names)


def _decorator_leaf(expr: ast.expr) -> str:
    if isinstance(expr, ast.Call):
        return _decorator_leaf(expr.func)
    if isinstance(expr, ast.Attribute):
        return expr.attr
    if isinstance(expr, ast.Name):
        return expr.id
    return ""


def _script_symbols(source: SourceFile) -> tuple[SymbolInfo, ...]:
    root = parse_root(source)
    if root is None:
        return ()
    found: list[SymbolInfo] = []
    for child in root.named_children:
        target = child
        if child.type == "export_statement":
            for inner in child.named_children:
                _collect_ts_node(inner, source.text, found)
        else:
            _collect_ts_node(target, source.text, found)
    return tuple(found)


def _collect_ts_node(node, full_text: str, found: list[SymbolInfo]) -> None:
    if node.type == "function_declaration":
        name_node = node.child_by_field_name("name")
        if name_node is None:
            return
        name = node_text(name_node)
        if not name or name.startswith("_"):
            return
        body = node_text(node)
        raises = tuple(m.group(1) for m in _JS_THROW_RE.finditer(body) if m.group(1))
        found.append(
            SymbolInfo(
                name=name,
                qualname=name,
                line=node.start_point[0] + 1,
                end_line=node.end_point[0] + 1,
                signature=body.splitlines()[0][:120],
                is_async=any(c.type == "async" for c in node.children),
                is_route=name in _HTTP_EXPORTS,
                raises_errors=bool(_JS_THROW_RE.search(body)),
                raised_types=raises,
            )
        )
    elif node.type in {"lexical_declaration", "variable_declaration"}:
        for decl in node.named_children:
            if decl.type != "variable_declarator":
                continue
            name_node = decl.child_by_field_name("name")
            value = decl.child_by_field_name("value")
            if name_node is None or value is None:
                continue
            if value.type not in {"arrow_function", "function_expression"}:
                continue
            name = node_text(name_node)
            if not name or name.startswith("_"):
                continue
            body = node_text(value)
            raises = tuple(m.group(1) for m in _JS_THROW_RE.finditer(body) if m.group(1))
            found.append(
                SymbolInfo(
                    name=name,
                    qualname=name,
                    line=decl.start_point[0] + 1,
                    end_line=decl.end_point[0] + 1,
                    signature=f"const {name} = {body.splitlines()[0][:100]}",
                    is_async=any(c.type == "async" for c in value.children),
                    is_route=name in _HTTP_EXPORTS,
                    raises_errors=bool(_JS_THROW_RE.search(body)),
                    raised_types=raises,
                )
            )
    elif node.type == "class_declaration":
        name_node = node.child_by_field_name("name")
        body = node.child_by_field_name("body")
        if name_node is None or body is None:
            return
        cls_name = node_text(name_node)
        if not cls_name or cls_name.startswith("_"):
            return
        for member in body.named_children:
            if member.type != "method_definition":
                continue
            mname_node = member.child_by_field_name("name")
            if mname_node is None:
                continue
            mname = node_text(mname_node)
            if not mname or mname.startswith("_") or mname.startswith("#") or mname == "constructor":
                continue
            mbody = node_text(member)
            found.append(
                SymbolInfo(
                    name=mname,
                    qualname=f"{cls_name}.{mname}",
                    line=member.start_point[0] + 1,
                    end_line=member.end_point[0] + 1,
                    signature=mbody.splitlines()[0][:120],
                    is_async=any(c.type == "async" for c in member.children),
                    is_route=False,
                    raises_errors=bool(_JS_THROW_RE.search(mbody)),
                )
            )
    del full_text


def _is_config_or_init_stub(sf: SourceFile) -> bool:
    pure = PurePosixPath(sf.path)
    if pure.name == "__init__.py" and len(sf.text.strip().splitlines()) <= 5:
        return True
    if pure.name.endswith(".d.ts"):
        return True
    return pure.name in {
        "setup.py",
        "conftest.py",
        "vite.config.ts",
        "vitest.config.ts",
        "jest.config.js",
        "jest.config.ts",
        "next.config.js",
        "next.config.mjs",
        "next.config.ts",
        "tailwind.config.js",
        "tailwind.config.ts",
    }


def _find_related_tests(
    source: SourceFile,
    symbols: tuple[SymbolInfo, ...],
    test_files: list[SourceFile],
) -> list[SourceFile]:
    stem = PurePosixPath(source.path).stem
    module_dotted = _dotted_module(source.path)
    sym_names = {sym.name for sym in symbols if len(sym.name) >= 3}
    matched: list[SourceFile] = []
    for test in test_files:
        test_name = PurePosixPath(test.path).name
        if (
            test_name in {f"test_{stem}.py", f"{stem}_test.py", f"{stem}.test.ts", f"{stem}.test.tsx", f"{stem}.test.js", f"{stem}.spec.ts", f"{stem}.spec.js"}
            or (module_dotted and module_dotted in test.text)
            or (stem and len(stem) >= 3 and re.search(rf"\b{re.escape(stem)}\b", test.text))
            or any(re.search(rf"\b{re.escape(name)}\b", test.text) for name in sym_names)
        ):
            matched.append(test)
    return matched


def _dotted_module(rel: str) -> str:
    pure = PurePosixPath(rel)
    parts = list(pure.with_suffix("").parts)
    if parts and parts[0] == "src":
        parts = parts[1:]
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _symbol_referenced(sym: SymbolInfo, text: str) -> bool:
    if not text:
        return False
    return bool(re.search(rf"\b{re.escape(sym.name)}\b", text))


def _audit_test_quality(test_files: list[SourceFile]) -> list[TestQualityIssue]:
    issues: list[TestQualityIssue] = []
    for sf in sorted(test_files, key=lambda item: item.path):
        if sf.language is Language.PYTHON:
            issues.extend(_audit_python_test(sf))
        elif sf.language in {Language.TYPESCRIPT, Language.TSX, Language.JAVASCRIPT}:
            issues.extend(_audit_js_test(sf))
    return issues


def _audit_python_test(sf: SourceFile) -> list[TestQualityIssue]:
    issues: list[TestQualityIssue] = []
    try:
        tree = ast.parse(sf.text)
    except SyntaxError:
        return [TestQualityIssue(sf.path, 1, "unparseable test file", "syntax error prevents test execution", Severity.HIGH)]

    test_funcs = [
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test_")
    ]
    if not test_funcs:
        if "test" in PurePosixPath(sf.path).name and sf.path != "tests/conftest.py" and not sf.path.endswith("/conftest.py"):
            issues.append(
                TestQualityIssue(sf.path, 1, "empty test suite", "test file defines zero test_* functions", Severity.MEDIUM)
            )
        return issues

    for fn in test_funcs:
        src = ast.get_source_segment(sf.text, fn) or ""
        has_assert = bool(_PY_ASSERT_RE.search(src))
        if not has_assert:
            issues.append(
                TestQualityIssue(sf.path, fn.lineno, "assertionless test", f"`{fn.name}` has no assertion or raises check", Severity.HIGH)
            )
        elif _PY_WEAK_ASSERT_RE.search(src) and len(re.findall(r"\bassert\b", src)) == 1 and "raises" not in src:
            issues.append(
                TestQualityIssue(sf.path, fn.lineno, "tautological assertion", f"`{fn.name}` only uses a trivial truthiness/not-None assertion", Severity.MEDIUM)
            )
    for marker in _SKIP_MARKERS_PY:
        if marker in sf.text:
            line = _first_line(sf.text, marker)
            issues.append(TestQualityIssue(sf.path, line, "skipped test", f"contains `{marker}`", Severity.LOW))
    for marker in _MOCK_MARKERS[:3]:
        if marker in sf.text:
            line = _first_line(sf.text, marker)
            issues.append(
                TestQualityIssue(sf.path, line, "mock-heavy test", f"uses `{marker}`; prefer real implementations over test doubles", Severity.LOW)
            )
            break
    return issues


def _audit_js_test(sf: SourceFile) -> list[TestQualityIssue]:
    issues: list[TestQualityIssue] = []
    has_test_call = bool(re.search(r"\b(?:it|test)\s*\(", sf.text))
    if not has_test_call:
        issues.append(TestQualityIssue(sf.path, 1, "empty test suite", "test file defines zero it()/test() blocks", Severity.MEDIUM))
        return issues
    if not _JS_ASSERT_RE.search(sf.text):
        issues.append(TestQualityIssue(sf.path, 1, "assertionless test", "test file contains no expect() or assert.* call", Severity.HIGH))
    elif _JS_WEAK_MATCHER_RE.search(sf.text) and not _JS_STRONG_MATCHER_RE.search(sf.text):
        line = _first_line(sf.text, "toBe")
        issues.append(
            TestQualityIssue(sf.path, line, "weak matcher only", "test file only uses weak matchers (toBeDefined/toBeTruthy) without value assertions", Severity.MEDIUM)
        )
    for marker in _SKIP_MARKERS_JS:
        if marker in sf.text:
            issues.append(TestQualityIssue(sf.path, _first_line(sf.text, marker), "skipped or focused test", f"contains `{marker}`", Severity.LOW))
            break
    for marker in _MOCK_MARKERS[3:]:
        if marker in sf.text:
            issues.append(TestQualityIssue(sf.path, _first_line(sf.text, marker), "mock-heavy test", f"uses `{marker}`; verify behavior against real code", Severity.LOW))
            break
    return issues


def _first_line(text: str, needle: str) -> int:
    for idx, row in enumerate(text.splitlines(), start=1):
        if needle in row:
            return idx
    return 1


def _gaps_for_module(mod: ModuleCoverage) -> list[CoverageGap]:
    gaps: list[CoverageGap] = []
    if not mod.related_tests and mod.symbols:
        sev = Severity.CRITICAL if mod.risk is RiskTier.HIGH else Severity.HIGH if mod.risk is RiskTier.MEDIUM else Severity.MEDIUM
        names = ", ".join(mod.untested_symbols[:5])
        extra = f" (+{len(mod.untested_symbols) - 5} more)" if len(mod.untested_symbols) > 5 else ""
        gaps.append(
            CoverageGap(
                kind=GapKind.MISSING_MODULE_TESTS,
                severity=sev,
                file=mod.path,
                line=mod.symbols[0].line,
                symbol=None,
                message=f"No tests cover `{mod.path}` ({len(mod.symbols)} public symbol(s): {names}{extra})",
                remediation=f"Create a test suite for `{mod.path}` covering happy paths and edge/error cases.",
                risk=mod.risk,
            )
        )
        return gaps

    if mod.untested_symbols:
        sev = Severity.HIGH if mod.risk is RiskTier.HIGH else Severity.MEDIUM
        sym_map = {sym.qualname: sym for sym in mod.symbols}
        for qname in mod.untested_symbols[:6]:
            sym = sym_map.get(qname)
            line = sym.line if sym is not None else 1
            gaps.append(
                CoverageGap(
                    kind=GapKind.UNTESTED_SYMBOL,
                    severity=sev,
                    file=mod.path,
                    line=line,
                    symbol=qname,
                    message=f"Public symbol `{qname}` in `{mod.path}` is not exercised by any test",
                    remediation=f"Add positive and edge-case tests for `{qname}`.",
                    risk=mod.risk,
                )
            )

    if mod.needs_error_path_tests and not mod.has_error_path_tests and mod.related_tests:
        sev = Severity.HIGH if mod.risk is RiskTier.HIGH else Severity.MEDIUM
        gaps.append(
            CoverageGap(
                kind=GapKind.MISSING_ERROR_PATHS,
                severity=sev,
                file=mod.path,
                line=mod.symbols[0].line if mod.symbols else 1,
                symbol=None,
                message=f"`{mod.path}` raises errors or handles routes, but its tests never assert error/rejection paths",
                remediation=f"Add negative tests (invalid input, raised exceptions, or error status codes) for `{mod.path}`.",
                risk=mod.risk,
            )
        )

    if mod.line_coverage_pct is not None and mod.line_coverage_pct < 70.0:
        sev = Severity.HIGH if mod.risk is RiskTier.HIGH else Severity.MEDIUM
        gaps.append(
            CoverageGap(
                kind=GapKind.LOW_LINE_COVERAGE,
                severity=sev,
                file=mod.path,
                line=mod.missed_lines[0] if mod.missed_lines else 1,
                symbol=None,
                message=f"Dynamic line coverage for `{mod.path}` is {mod.line_coverage_pct:.1f}% ({len(mod.missed_lines)} missed lines)",
                remediation=f"Add branch and boundary tests exercising uncovered lines in `{mod.path}`.",
                risk=mod.risk,
            )
        )
    return gaps


def _compute_score(modules: list[ModuleCoverage], quality_issues: list[TestQualityIssue]) -> int:
    if not modules:
        return 100
    total_weight = 0.0
    earned = 0.0
    for mod in modules:
        weight = 3.0 if mod.risk is RiskTier.HIGH else 2.0 if mod.risk is RiskTier.MEDIUM else 1.0
        total_weight += weight
        if mod.line_coverage_pct is not None:
            ratio = (mod.line_coverage_pct / 100.0) * 0.7 + mod.symbol_ratio * 0.3
        else:
            ratio = mod.symbol_ratio
        if mod.needs_error_path_tests and not mod.has_error_path_tests:
            ratio *= 0.85
        earned += weight * min(1.0, max(0.0, ratio))
    base = (earned / total_weight) * 100.0 if total_weight > 0 else 100.0
    penalty = sum(6.0 if i.severity is Severity.HIGH else 3.0 if i.severity is Severity.MEDIUM else 1.0 for i in quality_issues)
    return max(0, min(100, round(base - min(30.0, penalty))))


def _risk_rank(risk: RiskTier) -> int:
    return {RiskTier.HIGH: 0, RiskTier.MEDIUM: 1, RiskTier.LOW: 2}[risk]


_MONITOR_RUNNER = """
import ast, json, pathlib, sys, pytest

root = pathlib.Path(sys.argv[1]).resolve()
out_path = pathlib.Path(sys.argv[2])
executed = {}

def on_line(code, line_no):
    fn = code.co_filename
    if fn.startswith(str(root)):
        s = executed.get(fn)
        if s is None:
            s = set()
            executed[fn] = s
        s.add(line_no)
    return sys.monitoring.DISABLE

def exec_lines(path):
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, UnicodeDecodeError, SyntaxError):
        return set()
    lines = set()
    def walk(stmts):
        for idx, node in enumerate(stmts):
            if idx == 0 and isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                continue
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                lines.add(node.lineno); walk(node.body)
            elif isinstance(node, ast.If):
                if isinstance(node.test, ast.Name) and node.test.id == "TYPE_CHECKING":
                    continue
                lines.add(node.lineno); walk(node.body); walk(node.orelse)
            elif isinstance(node, (ast.For, ast.AsyncFor, ast.While)):
                lines.add(node.lineno); walk(node.body); walk(node.orelse)
            elif isinstance(node, (ast.With, ast.AsyncWith)):
                lines.add(node.lineno); walk(node.body)
            elif isinstance(node, ast.Try):
                lines.add(node.lineno); walk(node.body)
                for h in node.handlers:
                    lines.add(h.lineno); walk(h.body)
                walk(node.orelse); walk(node.finalbody)
            else:
                lines.add(node.lineno)
    walk(tree.body)
    return lines

if hasattr(sys, "monitoring"):
    tid = sys.monitoring.COVERAGE_ID
    sys.monitoring.use_tool_id(tid, "vibecleaner-target-cov")
    sys.monitoring.register_callback(tid, sys.monitoring.events.LINE, on_line)
    sys.monitoring.set_events(tid, sys.monitoring.events.LINE)
    rc = pytest.main(["-q", "--tb=no", "-p", "no:cacheprovider"])
    sys.monitoring.set_events(tid, 0)
    sys.monitoring.free_tool_id(tid)
else:
    def _trace(frame, event, arg):
        if event == "line":
            fn = frame.f_code.co_filename
            if fn.startswith(str(root)):
                executed.setdefault(fn, set()).add(frame.f_lineno)
        return _trace
    sys.settrace(_trace)
    try:
        rc = pytest.main(["-q", "--tb=no", "-p", "no:cacheprovider"])
    finally:
        sys.settrace(None)

report = {}
for path in root.rglob("*.py"):
    rel = path.relative_to(root).as_posix()
    if any(p in {".git", ".venv", "venv", "node_modules", "__pycache__", ".vibecleaner"} for p in path.parts):
        continue
    el = exec_lines(path)
    if not el:
        continue
    hit = executed.get(str(path.resolve()), set()) & el
    pct = round(100.0 * len(hit) / len(el), 1)
    report[rel] = {"pct": pct, "missed": sorted(el - hit)}

out_path.write_text(json.dumps({"rc": rc, "files": report}), encoding="utf-8")
"""


def _run_python_line_coverage(root: Path) -> tuple[dict[str, tuple[float, tuple[int, ...]]], bool, str | None]:
    """Run pytest under sys.monitoring (3.12+) or sys.settrace (3.11) without extra deps."""
    python_bin = _target_python(root)
    with tempfile.TemporaryDirectory(prefix="vibecleaner-cov-") as tmp:
        runner = Path(tmp) / "run_cov.py"
        out_file = Path(tmp) / "cov.json"
        runner.write_text(_MONITOR_RUNNER, encoding="utf-8")
        env = os.environ.copy()
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        env["PYTHONPATH"] = f"{root}{os.pathsep}{env.get('PYTHONPATH', '')}".rstrip(os.pathsep)
        try:
            proc = subprocess.run(
                [python_bin, str(runner), str(root), str(out_file)],
                cwd=root,
                env=env,
                capture_output=True,
                text=True,
                timeout=_DYNAMIC_COVERAGE_TIMEOUT_S,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return {}, False, f"Dynamic coverage failed: {exc}"
        if not out_file.is_file():
            detail = (proc.stderr or proc.stdout).strip().splitlines()[-1:] or ["pytest did not produce coverage data"]
            return {}, False, detail[0]
        try:
            payload = json.loads(out_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return {}, False, f"Could not read coverage output: {exc}"
        files = payload.get("files", {})
        result: dict[str, tuple[float, tuple[int, ...]]] = {}
        if isinstance(files, dict):
            for rel, info in files.items():
                if isinstance(info, dict) and isinstance(info.get("pct"), (int, float)):
                    missed = tuple(int(n) for n in info.get("missed", []) if isinstance(n, int))
                    result[str(rel)] = (float(info["pct"]), missed)
        rc = payload.get("rc")
        note = None if rc == 0 else f"pytest exited with code {rc} during dynamic coverage run"
        return result, True, note


def _target_python(root: Path) -> str:
    for rel in (".venv/bin/python", "venv/bin/python", ".venv/Scripts/python.exe"):
        candidate = root / rel
        if candidate.is_file():
            return str(candidate)
    return sys.executable


def _read_js_coverage_summary(root: Path) -> tuple[dict[str, tuple[float, tuple[int, ...]]], bool, str | None]:
    """Read Vitest/Jest Istanbul ``coverage/coverage-summary.json`` if present."""
    summary_path = root / "coverage" / "coverage-summary.json"
    if not summary_path.is_file():
        return {}, False, None
    try:
        payload = json.loads(summary_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        return {}, False, f"Could not read {summary_path.name}: {exc}"
    if not isinstance(payload, dict):
        return {}, False, None
    resolved_root = root.resolve()
    result: dict[str, tuple[float, tuple[int, ...]]] = {}
    for key, entry in payload.items():
        if key == "total" or not isinstance(entry, dict):
            continue
        lines_info = entry.get("lines")
        if not isinstance(lines_info, dict) or not isinstance(lines_info.get("pct"), (int, float)):
            continue
        path = Path(key)
        if path.is_absolute():
            try:
                rel = path.resolve().relative_to(resolved_root).as_posix()
            except ValueError:
                continue
        else:
            rel = PurePosixPath(key.replace("\\", "/")).as_posix()
        result[rel] = (float(lines_info["pct"]), ())
    return result, bool(result), None


def _discover_test_files(root: Path) -> list[SourceFile]:
    """Walk ``root`` for test files even when ``.vibecleanerignore`` excludes ``tests/``."""
    found: list[SourceFile] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(name for name in dirnames if name not in _TEST_WALK_SKIP)
        for name in sorted(filenames):
            path = Path(dirpath) / name
            lang = _SUFFIX_TO_LANG.get(path.suffix.lower())
            if lang is None:
                continue
            rel = path.relative_to(root).as_posix()
            if not _is_test_unit_path(rel):
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            found.append(SourceFile(path=rel, abs_path=path, language=lang, text=text))
    return found
