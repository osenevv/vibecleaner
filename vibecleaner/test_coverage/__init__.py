"""Audit test coverage and implement missing test suites for any target repository."""

from __future__ import annotations

from vibecleaner.test_coverage.audit import audit_test_coverage, detect_frameworks, extract_symbols
from vibecleaner.test_coverage.generate import generate_missing_tests
from vibecleaner.test_coverage.models import (
    CoverageGap,
    CoverageReport,
    GapKind,
    GeneratedTestResult,
    GenerationSummary,
    ModuleCoverage,
    SymbolInfo,
    TestFramework,
    TestQualityIssue,
)
from vibecleaner.test_coverage.prompts import build_test_prompt, render_coverage_markdown

__all__ = [
    "CoverageGap",
    "CoverageReport",
    "GapKind",
    "GeneratedTestResult",
    "GenerationSummary",
    "ModuleCoverage",
    "SymbolInfo",
    "TestFramework",
    "TestQualityIssue",
    "audit_test_coverage",
    "build_test_prompt",
    "detect_frameworks",
    "extract_symbols",
    "generate_missing_tests",
    "render_coverage_markdown",
]
