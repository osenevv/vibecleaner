"""Render test-coverage Markdown reports and AI agent test-implementation prompts."""

from __future__ import annotations

from vibecleaner.test_coverage.models import CoverageReport, GenerationSummary


def render_coverage_markdown(report: CoverageReport, generation: GenerationSummary | None = None) -> str:
    """Render a clear, actionable Markdown report for ``VIBECLEANER_TESTS.md``."""
    scope = f"files changed since `{report.diff_base}`" if report.diff_base else "the full repository"
    frameworks = ", ".join(fw.value for fw in report.frameworks)
    lines = [
        "# Test Coverage & Quality Audit",
        "",
        f"- **Score:** {report.coverage_score}/100 ({scope})",
        f"- **Frameworks:** {frameworks}",
        f"- **Modules covered:** {report.tested_modules}/{report.total_modules}",
        f"- **Public symbols covered:** {report.tested_symbols}/{report.total_symbols}",
        f"- **Existing test files:** {report.test_files_count}",
        f"- **Gaps found:** {len(report.gaps)} ({len(report.quality_issues)} test-quality issue(s))",
    ]
    if report.dynamic_coverage_ran:
        lines.append("- **Dynamic line coverage:** enabled (Python `sys.monitoring`)")
    if report.dynamic_coverage_note:
        lines.append(f"- **Coverage note:** {report.dynamic_coverage_note}")
    lines.append("")

    if generation is not None and generation.results:
        lines.extend(
            [
                "## Generated Test Suites",
                "",
                f"Created {generation.created_count} test file(s), {generation.verified_count} verified green.",
                "",
                "| Source | Test file | Status | Detail |",
                "| --- | --- | --- | --- |",
            ]
        )
        for item in generation.results:
            lines.append(f"| `{item.source_file}` | `{item.test_file}` | `{item.status}` | {item.detail} |")
        lines.append("")

    if report.gaps:
        lines.extend(
            [
                "## Prioritized Coverage Gaps",
                "",
                "| Severity | Risk | Kind | Location | Detail |",
                "| --- | --- | --- | --- | --- |",
            ]
        )
        for gap in report.gaps:
            loc = f"`{gap.file}:{gap.line}`"
            lines.append(f"| {gap.severity.value.upper()} | {gap.risk.value} | `{gap.kind.value}` | {loc} | {gap.message} |")
        lines.append("")
    else:
        lines.append("No test coverage or test quality gaps detected.")
        lines.append("")

    if report.modules:
        lines.extend(
            [
                "## Module Breakdown",
                "",
                "| Module | Risk | Symbols Tested | Error Paths | Line Coverage | Related Tests |",
                "| --- | --- | --- | --- | --- | --- |",
            ]
        )
        for mod in report.modules:
            sym_cell = f"{len(mod.tested_symbols)}/{len(mod.symbols)}"
            err_cell = "yes" if mod.has_error_path_tests else ("missing" if mod.needs_error_path_tests else "n/a")
            line_cell = f"{mod.line_coverage_pct:.1f}%" if mod.line_coverage_pct is not None else "—"
            tests_cell = ", ".join(f"`{t}`" for t in mod.related_tests[:3]) or "*(none)*"
            lines.append(f"| `{mod.path}` | {mod.risk.value} | {sym_cell} | {err_cell} | {line_cell} | {tests_cell} |")
        lines.append("")

    return "\n".join(lines)


def build_test_prompt(report: CoverageReport, *, max_gaps: int = 25) -> str:
    """Build a self-contained prompt an AI coding agent can execute to implement missing/weak tests."""
    if not report.gaps:
        return ""
    selected = report.gaps[:max_gaps]
    frameworks = ", ".join(fw.value for fw in report.frameworks)
    lines = [
        f"Implement missing and incomplete test suites in this repository (current coverage score: {report.coverage_score}/100, frameworks: {frameworks}):",
        "",
    ]
    for index, gap in enumerate(selected, start=1):
        lines.append(
            f"{index}. {gap.file}:{gap.line} [{gap.severity.value.upper()} {gap.kind.value}, risk={gap.risk.value}]: {gap.message}"
        )
        lines.append(f"   Action: {gap.remediation}")
    lines.extend(
        [
            "",
            "Rules:",
            "- Write real, deterministic tests against real production implementations instead of test doubles.",
            "- For every new or strengthened test, cover: (1) normal happy path with concrete output assertions, (2) boundary/empty/edge inputs, and (3) error/rejection paths.",
            "- Never delete existing tests, add skip/xfail markers, use fixed sleeps, or weaken assertions.",
            "- Run the project's full test suite and confirm every test passes before finishing.",
        ]
    )
    return "\n".join(lines)
