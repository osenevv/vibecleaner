"""Typed contracts for auditing and generating test coverage on any target app."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from vibecleaner.models import RiskTier, Severity


class GapKind(str, Enum):
    MISSING_MODULE_TESTS = "missing_module_tests"
    UNTESTED_SYMBOL = "untested_symbol"
    MISSING_ERROR_PATHS = "missing_error_paths"
    LOW_LINE_COVERAGE = "low_line_coverage"
    LACKLUSTER_TEST = "lackluster_test"


class TestFramework(str, Enum):
    __test__ = False

    PYTEST = "pytest"
    VITEST = "vitest"
    JEST = "jest"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class SymbolInfo:
    """A public callable or class in a production module."""

    name: str
    qualname: str
    line: int
    end_line: int
    signature: str
    is_async: bool
    is_route: bool
    raises_errors: bool
    parameters: tuple[tuple[str, str, str], ...] = ()  # (name, annotation, default)
    return_annotation: str = ""
    raised_types: tuple[str, ...] = ()


@dataclass(frozen=True)
class CoverageGap:
    """A concrete coverage or test-quality gap in the target repository."""

    kind: GapKind
    severity: Severity
    file: str
    line: int
    symbol: str | None
    message: str
    remediation: str
    risk: RiskTier = RiskTier.MEDIUM

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind.value,
            "severity": self.severity.value,
            "file": self.file,
            "line": self.line,
            "symbol": self.symbol,
            "message": self.message,
            "remediation": self.remediation,
            "risk": self.risk.value,
        }


@dataclass(frozen=True)
class TestQualityIssue:
    """A weakness detected inside an existing test file."""

    __test__ = False

    file: str
    line: int
    reason: str
    detail: str
    severity: Severity = Severity.MEDIUM

    def to_dict(self) -> dict[str, object]:
        return {
            "file": self.file,
            "line": self.line,
            "reason": self.reason,
            "detail": self.detail,
            "severity": self.severity.value,
        }


@dataclass(frozen=True)
class ModuleCoverage:
    """Coverage summary for one production source file."""

    path: str
    language: str
    risk: RiskTier
    symbols: tuple[SymbolInfo, ...]
    tested_symbols: tuple[str, ...]
    untested_symbols: tuple[str, ...]
    related_tests: tuple[str, ...]
    has_error_path_tests: bool
    needs_error_path_tests: bool
    line_coverage_pct: float | None = None
    missed_lines: tuple[int, ...] = ()

    @property
    def symbol_ratio(self) -> float:
        if not self.symbols:
            return 1.0 if self.related_tests else 0.0
        return len(self.tested_symbols) / len(self.symbols)

    def to_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "language": self.language,
            "risk": self.risk.value,
            "total_symbols": len(self.symbols),
            "tested_symbols": list(self.tested_symbols),
            "untested_symbols": list(self.untested_symbols),
            "related_tests": list(self.related_tests),
            "has_error_path_tests": self.has_error_path_tests,
            "needs_error_path_tests": self.needs_error_path_tests,
            "line_coverage_pct": self.line_coverage_pct,
            "missed_lines": list(self.missed_lines[:40]),
        }


@dataclass(frozen=True)
class CoverageReport:
    """Complete test-coverage audit for a target repository."""

    root: Path
    frameworks: tuple[TestFramework, ...]
    coverage_score: int
    modules: tuple[ModuleCoverage, ...]
    gaps: tuple[CoverageGap, ...]
    quality_issues: tuple[TestQualityIssue, ...]
    test_files_count: int
    dynamic_coverage_ran: bool = False
    dynamic_coverage_note: str | None = None
    diff_base: str | None = None

    @property
    def total_modules(self) -> int:
        return len(self.modules)

    @property
    def tested_modules(self) -> int:
        return sum(1 for mod in self.modules if mod.related_tests or (mod.line_coverage_pct or 0.0) > 0.0)

    @property
    def total_symbols(self) -> int:
        return sum(len(mod.symbols) for mod in self.modules)

    @property
    def tested_symbols(self) -> int:
        return sum(len(mod.tested_symbols) for mod in self.modules)

    def to_dict(self) -> dict[str, object]:
        return {
            "root": str(self.root),
            "frameworks": [fw.value for fw in self.frameworks],
            "coverage_score": self.coverage_score,
            "total_modules": self.total_modules,
            "tested_modules": self.tested_modules,
            "total_symbols": self.total_symbols,
            "tested_symbols": self.tested_symbols,
            "test_files_count": self.test_files_count,
            "dynamic_coverage_ran": self.dynamic_coverage_ran,
            "dynamic_coverage_note": self.dynamic_coverage_note,
            "diff_base": self.diff_base,
            "gaps": [gap.to_dict() for gap in self.gaps],
            "quality_issues": [issue.to_dict() for issue in self.quality_issues],
            "modules": [mod.to_dict() for mod in self.modules],
        }


@dataclass(frozen=True)
class GeneratedTestResult:
    """Outcome of generating (and optionally verifying) one test file."""

    source_file: str
    test_file: str
    framework: TestFramework
    status: str  # verified | created | failed_rolled_back | failed_kept | skipped
    tests_generated: int
    detail: str
    output: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "source_file": self.source_file,
            "test_file": self.test_file,
            "framework": self.framework.value,
            "status": self.status,
            "tests_generated": self.tests_generated,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class GenerationSummary:
    """Aggregate result of a test-generation run."""

    results: tuple[GeneratedTestResult, ...] = field(default_factory=tuple)
    tamper_blocked: bool = False
    tamper_detail: str = ""

    @property
    def created_count(self) -> int:
        return sum(1 for item in self.results if item.status in {"verified", "created", "failed_kept"})

    @property
    def verified_count(self) -> int:
        return sum(1 for item in self.results if item.status == "verified")

    def to_dict(self) -> dict[str, object]:
        return {
            "created_count": self.created_count,
            "verified_count": self.verified_count,
            "tamper_blocked": self.tamper_blocked,
            "tamper_detail": self.tamper_detail,
            "results": [item.to_dict() for item in self.results],
        }
