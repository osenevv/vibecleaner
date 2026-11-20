"""Markdown and JSON renderers for a launch report."""

from __future__ import annotations

from vibeguard.preflight.results import PreflightReport, _AGENT_RULES, _STATUS_LABEL


def _cell(value: str) -> str:
    return " ".join(value.replace("|", "\\|").replace("\r", " ").split())


def _bullet(report: PreflightReport, ids: list[int]) -> list[str]:
    by_id = {check.id: check for check in report.checks}
    lines: list[str] = []
    for check_id in ids:
        check = by_id[check_id]
        lines.append(f"- #{check.id} {check.title} ({_STATUS_LABEL[check.status]})")
    return lines or ["None."]


def render_preflight_markdown(report: PreflightReport) -> str:
    """Render the launch table, blockers, and the rules for a follow-up agent."""
    stack = ", ".join(report.stack) if report.stack else "(none detected)"
    lines = [
        "# VibeGuard launch preflight",
        "",
        report.summary,
        "",
        f"**Stack:** {stack}",
        "",
        "| # | Section | Check | Status | Found | Evidence | Consequence | Verify |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for check in report.checks:
        cells = [
            str(check.id),
            _cell(check.section),
            _cell(check.title),
            _cell(_STATUS_LABEL[check.status]),
            _cell(check.found),
            _cell(check.evidence),
            _cell(check.consequence),
            _cell(check.verify),
        ]
        lines.append("| " + " | ".join(cells) + " |")
    lines.extend(["", "## Blocks launch", ""])
    lines.extend(_bullet(report, report.blockers))
    lines.extend(["", "## Can wait", ""])
    lines.extend(_bullet(report, report.can_wait))
    lines.extend(["", "## First three actions", ""])
    for index, action in enumerate(report.first_actions, start=1):
        lines.append(f"{index}. {action}")
    lines.extend(["", "## Agent rules", "", _AGENT_RULES, ""])
    return "\n".join(lines)


def preflight_to_json(report: PreflightReport) -> dict[str, object]:
    """Serialize a report. Status values are the enum strings, not labels."""
    return {
        "summary": report.summary,
        "stack": list(report.stack),
        "checks": [
            {
                "id": check.id,
                "section": check.section,
                "title": check.title,
                "status": check.status.value,
                "found": check.found,
                "evidence": check.evidence,
                "consequence": check.consequence,
                "verify": check.verify,
                "locations": list(check.locations),
            }
            for check in report.checks
        ],
        "blockers": list(report.blockers),
        "can_wait": list(report.can_wait),
        "first_actions": list(report.first_actions),
    }
