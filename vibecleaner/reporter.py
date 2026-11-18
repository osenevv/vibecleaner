"""Terminal, Markdown, SARIF, and JSON renderers for a scan result."""

from __future__ import annotations

import json
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.text import Text

from vibecleaner import __version__
from vibecleaner.models import PROJECT_RULE_PREFIX, RULES, Category, Finding, RuleSpec, ScanResult, Severity
from vibecleaner.prompt_fix import build_fix_prompt, plain_explanation
from vibecleaner.redact import redact_secrets

INPUT_USD_PER_MILLION = 0.10
_PENALTY = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 15,
    Severity.MEDIUM: 8,
    Severity.LOW: 3,
}
_SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_INFO_URI = "https://github.com/vibecleaner/vibecleaner"
_SEVERITY_ORDER = (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)


def estimated_cost(input_tokens: int) -> float:
    return input_tokens * INPUT_USD_PER_MILLION / 1_000_000


def compute_scores(findings: list[Finding]) -> tuple[int, int]:
    """Return ``(security_score, slop_score)`` in ``0..100``.

    Layer 1 findings pay the full severity penalty. Layer 2 penalties are
    scaled by the calibrated probability.
    """
    security = 0.0
    slop = 0.0
    for finding in findings:
        penalty = float(_PENALTY[finding.severity])
        if finding.layer == 2:
            scale = 1.0 if finding.probability is None else float(finding.probability)
            penalty *= scale
        if finding.category == Category.SECURITY:
            security += penalty
        else:
            slop += penalty
    return _clamp_score(100.0 - security), _clamp_score(100.0 - slop)


def _clamp_score(value: float) -> int:
    if value < 0:
        value = 0
    elif value > 100:
        value = 100
    return int(round(value))


def _probability(finding: Finding) -> float:
    if finding.probability is None:
        return 1.0
    return float(finding.probability)


def _compact_line(finding: Finding) -> str:
    return (
        f"{finding.severity.value.upper()} {finding.rule_id} "
        f"{finding.file}:{finding.line} (p={_probability(finding):.2f}) {finding.message}"
    )


def render_terminal(result: ScanResult, console: Console, quiet: bool = False) -> None:
    """Print a quiet one-line-per-finding report, or a rich table."""
    if quiet:
        _render_quiet(result, console)
        return
    _render_full(result, console)


def _render_quiet(result: ScanResult, console: Console) -> None:
    if result.judge.errors:
        for finding in result.findings:
            console.print(_compact_line(finding), markup=False, highlight=False)
        console.print(_quiet_error(result), markup=False, highlight=False)
        return
    if not result.findings:
        console.print("VIBECLEANER: PASS", markup=False, highlight=False)
        return
    for finding in result.findings:
        console.print(_compact_line(finding), markup=False, highlight=False)
    security, slop = compute_scores(result.findings)
    console.print(
        f"VIBECLEANER: FAIL findings={len(result.findings)} security={security} slop={slop}",
        markup=False,
        highlight=False,
    )


def _quiet_error(result: ScanResult) -> str:
    count = len(result.judge.errors)
    detail = "; ".join(result.judge.errors)
    return f"VIBECLEANER: ERROR {count} Layer-2 chunk(s) failed: {detail}"


def _render_full(result: ScanResult, console: Console) -> None:
    security, slop = compute_scores(result.findings)
    judge = result.judge
    cost = estimated_cost(judge.input_tokens)
    console.print(
        f"[bold]VibeCleaner[/bold]  security={security}  slop={slop}  mode={judge.mode}"
    )
    console.print(
        f"files scanned: {result.files_scanned}  "
        f"units judged: {judge.units_judged}  "
        f"cache hits: {judge.cache_hits}"
    )
    console.print(f"input tokens: {judge.input_tokens}  estimated cost: ${cost:.6f} ($0.10/1M)")
    if result.review is not None:
        console.print(f"review tier {result.review.tier}: {result.review.reason}", markup=False)
    if judge.errors:
        console.print(
            f"[bold red]ERROR[/bold red] {len(judge.errors)} Layer-2 chunk(s) failed"
        )
        for error in judge.errors:
            line = Text()
            line.append("ERROR: ", style="bold red")
            line.append(error)
            console.print(line)
    if result.findings:
        console.print(_findings_table(result.findings))
        console.print()
        console.print("[bold]Plain-English summary:[/bold]")
        for index, finding in enumerate(result.findings, start=1):
            risk, fix = plain_explanation(finding)
            console.print(f"  {index}. {risk} ({finding.file}:{finding.line})", markup=False)
            console.print(f"     Fix: {fix}", markup=False)
        prompt = build_fix_prompt(result)
        if prompt:
            console.print()
            console.print("[bold]Copy and paste this into your AI coding agent (or run `vibecleaner --autofix`):[/bold]")
            console.print(prompt, markup=False)
    else:
        console.print("[bold green]PASS[/bold green] no findings")
    skipped = judge.units_skipped_layer1
    console.print(
        f"{len(result.findings)} finding(s) in {result.duration_s:.2f}s"
        + (f"  skipped {skipped} unit(s) after layer 1" if skipped else "")
    )


def _findings_table(findings: list[Finding]) -> Table:
    table = Table(title="Findings", show_lines=True, expand=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Prob", justify="right", no_wrap=True)
    table.add_column("Finding", overflow="fold", ratio=1)
    for finding in findings:
        prob = "exact" if finding.probability is None else f"{finding.probability:.2f}"
        detail = Text()
        detail.append(finding.rule_id, style="bold")
        detail.append(f"  {finding.file}:{finding.line}\n", style="cyan")
        detail.append(finding.message)
        table.add_row(Text(finding.severity.value, style=_severity_style(finding.severity)), prob, detail)
    return table


def _severity_style(severity: Severity) -> str:
    return {
        Severity.CRITICAL: "bold red",
        Severity.HIGH: "red",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "dim",
    }[severity]


def to_markdown(result: ScanResult) -> str:
    security, slop = compute_scores(result.findings)
    judge = result.judge
    lines = [
        "# VibeCleaner report",
        "",
        f"- Security score: {security}",
        f"- Slop score: {slop}",
        f"- Mode: {judge.mode}",
        f"- Files scanned: {result.files_scanned}",
        f"- Units judged: {judge.units_judged}",
        f"- Units skipped (layer 1): {judge.units_skipped_layer1}",
        f"- Cache hits: {judge.cache_hits}",
        f"- Requests: {judge.requests}",
        f"- Input tokens: {judge.input_tokens}",
        f"- Estimated cost: ${estimated_cost(judge.input_tokens):.6f}",
        f"- Duration: {result.duration_s:.2f}s",
    ]
    if result.diff_base:
        lines.append(f"- Diff base: {result.diff_base}")
    lines.append("")
    if judge.errors:
        lines.append("## Warnings")
        lines.append("")
        for error in judge.errors:
            lines.append(f"- {error}")
        lines.append("")
    lines.extend(_review_lines(result))
    lines.append("## Findings")
    lines.append("")
    if not result.findings:
        lines.append("No findings.")
        lines.append("")
        return "\n".join(lines)
    grouped: dict[Severity, list[Finding]] = {severity: [] for severity in _SEVERITY_ORDER}
    for finding in result.findings:
        grouped[finding.severity].append(finding)
    for severity in _SEVERITY_ORDER:
        items = grouped[severity]
        if not items:
            continue
        lines.append(f"### {severity.value}")
        lines.append("")
        lines.append("| Rule | Location | Prob | Risk | Message |")
        lines.append("| --- | --- | --- | --- | --- |")
        for finding in items:
            prob = "" if finding.probability is None else f"{finding.probability:.2f}"
            location = f"{finding.file}:{finding.line}"
            lines.append(
                "| {rule} | {location} | {prob} | {risk} | {message} |".format(
                    rule=finding.rule_id,
                    location=markdown_cell(location),
                    prob=prob,
                    risk=_risk_cell(finding),
                    message=markdown_cell(finding.message),
                )
            )
        lines.append("")
        seen: set[str] = set()
        for finding in items:
            if finding.rule_id in seen:
                continue
            seen.add(finding.rule_id)
            lines.append(f"**{finding.rule_id}**: {finding.spec.remediation}")
            lines.append("")
        for finding in items:
            if not finding.fix_patch:
                continue
            lines.append(f"#### {finding.file}:{finding.line} {finding.rule_id}")
            lines.append("")
            lines.append("```diff")
            lines.append(redact_secrets(finding.fix_patch).strip("\n"))
            lines.append("```")
            lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def markdown_cell(text: str) -> str:
    """Escape a Markdown table cell. Newlines become spaces; other whitespace stays."""
    return text.replace("|", "\\|").replace("\n", " ")


def _risk_cell(finding: Finding) -> str:
    if finding.module_risk is None:
        return ""
    return f"{finding.module_risk:.2f}"


def write_markdown(result: ScanResult, path: Path | str) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(to_markdown(result), encoding="utf-8")


def to_sarif(result: ScanResult) -> dict[str, object]:
    """SARIF 2.1.0 document. Paths are repo-relative POSIX."""
    results = []
    for finding in result.findings:
        end_line = finding.end_line if finding.end_line is not None else finding.line
        results.append(
            {
                "ruleId": finding.rule_id,
                "level": _sarif_level(finding.severity),
                "message": {"text": finding.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": _artifact_uri(result, finding.file)},
                            "region": {"startLine": finding.line, "endLine": end_line},
                        }
                    }
                ],
                "properties": {
                    "probability": finding.probability,
                    "layer": finding.layer,
                    "module_risk": finding.module_risk,
                },
            }
        )
    return {
        "$schema": _SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "VibeCleaner",
                        "version": __version__,
                        "informationUri": _INFO_URI,
                        "rules": [_sarif_rule(spec) for spec in _rules_for_result(result)],
                    }
                },
                "results": results,
            }
        ],
    }


def _rules_for_result(result: ScanResult) -> list[RuleSpec]:
    """Built-in rules, the scan's project rules, and ``P.*`` ids on its findings."""
    specs = [spec for spec in RULES.values() if not spec.rule_id.startswith(PROJECT_RULE_PREFIX)]
    seen = {spec.rule_id for spec in specs}
    for spec in result.project_rule_specs:
        _append_project_spec(specs, seen, spec)
    for finding in result.findings:
        if finding.rule_id in seen or not finding.rule_id.startswith(PROJECT_RULE_PREFIX):
            continue
        spec = finding.rule_spec or RULES.get(finding.rule_id)
        if spec is not None:
            _append_project_spec(specs, seen, spec)
    return specs


def _append_project_spec(specs: list[RuleSpec], seen: set[str], spec: RuleSpec) -> None:
    if spec.rule_id in seen or not spec.rule_id.startswith(PROJECT_RULE_PREFIX):
        return
    specs.append(spec)
    seen.add(spec.rule_id)


def _sarif_rule(spec: RuleSpec) -> dict[str, object]:
    return {
        "id": spec.rule_id,
        "name": spec.title,
        "shortDescription": {"text": spec.title},
        "help": {"text": spec.remediation},
        "properties": {
            "category": spec.category.value,
            "severity": spec.severity.value,
            "layer": spec.layer,
        },
    }


def _sarif_level(severity: Severity) -> str:
    if severity in (Severity.CRITICAL, Severity.HIGH):
        return "error"
    if severity == Severity.MEDIUM:
        return "warning"
    return "note"


def _artifact_uri(result: ScanResult, file: str) -> str:
    text = file.replace("\\", "/")
    path = Path(text)
    if path.is_absolute():
        try:
            path = path.relative_to(Path(result.root))
        except ValueError:
            return path.as_posix()
    posix = path.as_posix()
    return posix[2:] if posix.startswith("./") else posix


def write_sarif(result: ScanResult, path: Path | str) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(to_sarif(result), indent=2) + "\n",
        encoding="utf-8",
    )


def to_json(result: ScanResult) -> dict[str, object]:
    security, slop = compute_scores(result.findings)
    judge = result.judge
    return {
        "version": __version__,
        "root": Path(result.root).as_posix(),
        "diff_base": result.diff_base,
        "security_score": security,
        "slop_score": slop,
        "files_scanned": result.files_scanned,
        "duration_s": result.duration_s,
        "judge": {
            "mode": judge.mode,
            "units_judged": judge.units_judged,
            "units_skipped_layer1": judge.units_skipped_layer1,
            "cache_hits": judge.cache_hits,
            "requests": judge.requests,
            "input_tokens": judge.input_tokens,
            "estimated_cost_usd": estimated_cost(judge.input_tokens),
            "errors": list(judge.errors),
        },
        "review": _review_json(result),
        "findings": [_finding_json(finding) for finding in result.findings],
    }


def _review_json(result: ScanResult) -> dict[str, object] | None:
    review = result.review
    if review is None:
        return None
    return {
        "tier": review.tier,
        "reason": review.reason,
        "human_review": list(review.human_review),
        "file_risk": {path: tier.value for path, tier in sorted(review.file_risk.items())},
    }


def _review_lines(result: ScanResult) -> list[str]:
    review = result.review
    if review is None:
        return []
    lines = ["## Review routing", "", f"Tier {review.tier}: {review.reason}", ""]
    if review.human_review:
        lines.append("A person should read:")
        lines.append("")
        lines.extend(f"- `{path}`" for path in review.human_review)
        lines.append("")
    return lines


def _finding_json(finding: Finding) -> dict[str, object]:
    return {
        "rule_id": finding.rule_id,
        "file": finding.file,
        "line": finding.line,
        "end_line": finding.end_line,
        "symbol": finding.symbol,
        "message": finding.message,
        "probability": finding.probability,
        "severity": finding.severity.value,
        "category": finding.category.value,
        "layer": finding.layer,
        "detector": finding.detector,
        "snippet": finding.snippet,
        "fix_patch": redact_secrets(finding.fix_patch) if finding.fix_patch else None,
        "module_risk": finding.module_risk,
    }
