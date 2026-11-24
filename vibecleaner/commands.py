"""`deslop`, `preflight`, and `rule` subcommands."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from vibecleaner.cleanup import FixReport, fix_tree, revert_rule
from vibecleaner.collector import CollectorError, collect
from vibecleaner.deslop import CONCERN_BRIEFS, DESLOP_CONCERNS, slop_score
from vibecleaner.deterministic import run_deterministic
from vibecleaner.init_cmd import render_init_summary, run_init
from vibecleaner.models import PROJECT_RULE_PREFIX, Category, Finding, Severity
from vibecleaner.preflight import Status, preflight_to_json, render_preflight_markdown, run_preflight
from vibecleaner.project_rules import (
    DEFAULT_DESLOP_LANE,
    DESLOP_LANES,
    BoundaryRule,
    PatternRule,
    ProjectRules,
    ProjectRulesError,
    add_boundary_rule,
    add_pattern_rule,
    apply_project_rules,
    load_project_rules,
    rule_hits_preview,
)
from vibecleaner.reporter import markdown_cell, write_rows_sarif

_FAIL_CHOICES = ("critical", "high", "medium", "low", "none")
_FAMILY_LANES = {"D8": "defensive-code"}


def add_subcommands(sub: argparse._SubParsersAction) -> None:
    init = sub.add_parser("init", help="set up .gitignore, git pre-push hook, and detected AI-editor rules")
    init.add_argument("path", nargs="?", default=".", help="repository root (default: .)")
    init.add_argument("--no-hook", action="store_true", help="do not install .git/hooks/pre-push")
    init.add_argument("--antigravity", action="store_true", help="install workspace Antigravity plugin")
    init.add_argument("--cursor", action="store_true", help="install .cursor/rules/vibecleaner.mdc")
    init.add_argument("--claude", action="store_true", help="install .claude/rules/vibecleaner.md")
    init.add_argument("--ci", action="store_true", help="install .github/workflows/vibecleaner.yml")
    init.add_argument("--force", action="store_true", help="overwrite existing managed hooks or rule files")
    init.add_argument("--json", action="store_true", help="print JSON to stdout and nothing else")

    fix = sub.add_parser("fix", help="delete proven slop, then ask the host to finish the rest")
    fix.add_argument("path", nargs="?", default=".", help="repository root (default: .)")
    fix.add_argument("--no-host", action="store_true", help="apply only edits a detector can prove")
    fix.add_argument("--revert", default=None, metavar="RULE", help="undo one rule and re-apply the others")
    fix.add_argument("--sarif", default=None, metavar="PATH", help="write remaining findings as SARIF 2.1.0")
    fix.add_argument("--json", action="store_true", help="print JSON to stdout and nothing else")

    deslop = sub.add_parser("deslop", help="group slop findings into eight cleanup lanes for narrow agents")
    deslop.add_argument("path", nargs="?", default=".")
    deslop.add_argument("--diff", dest="diff_base", default=None, metavar="BASE", help="only files changed since BASE")
    deslop.add_argument("--out", default=None, metavar="PATH", help="default: <root>/VIBECLEANER_DESLOP.md")
    deslop.add_argument("--json", action="store_true", help="print JSON to stdout and nothing else")
    deslop.add_argument(
        "--fail-on",
        choices=_FAIL_CHOICES,
        default="medium",
        help="exit 1 when a finding is at or above this severity (default: medium)",
    )

    preflight = sub.add_parser("preflight", help="42 launch-readiness checks from code evidence (read-only)")
    preflight.add_argument("path", nargs="?", default=".")
    preflight.add_argument("--out", default=None, metavar="PATH", help="default: <root>/VIBECLEANER_PREFLIGHT.md")
    preflight.add_argument("--json", action="store_true", help="print JSON to stdout and nothing else")

    rule = sub.add_parser("rule", help="turn a correction into a project rule in .vibecleaner/rules.json")
    actions = rule.add_subparsers(dest="rule_command", required=True)
    pattern = actions.add_parser("add-pattern", help="ban a construct with a regex")
    pattern.add_argument("rule_id")
    pattern.add_argument("--pattern", required=True)
    pattern.add_argument("--message", required=True)
    pattern.add_argument("--include", action="append", default=None, metavar="GLOB")
    pattern.add_argument("--exclude", action="append", default=None, metavar="GLOB")
    pattern.add_argument("--severity", choices=("critical", "high", "medium", "low"), default="high")
    pattern.add_argument("--category", choices=("security", "slop"), default="slop")
    pattern.add_argument("--remediation", default=None)
    pattern.add_argument("--learned-from", default=None, help="the correction that produced this rule")
    pattern.add_argument(
        "--lane",
        choices=DESLOP_LANES,
        default=None,
        help="deslop cleanup lane for this pattern (default: ai-slop)",
    )
    pattern.add_argument("--path", default=".")
    pattern.add_argument("--preview", action="store_true", help="show hits and do not save")

    boundary = actions.add_parser("add-boundary", help="forbid imports across an architectural boundary")
    boundary.add_argument("rule_id")
    boundary.add_argument("--from", dest="from_globs", action="append", required=True, metavar="GLOB")
    boundary.add_argument("--forbid", action="append", required=True, metavar="GLOB_OR_PACKAGE")
    boundary.add_argument("--message", required=True)
    boundary.add_argument("--severity", choices=("critical", "high", "medium", "low"), default="high")
    boundary.add_argument("--learned-from", default=None)
    boundary.add_argument("--path", default=".")
    boundary.add_argument("--preview", action="store_true", help="show hits and do not save")

    listing = actions.add_parser("list", help="list project rules and how many lines each flags")
    listing.add_argument("--path", default=".")


def run_subcommand(args: argparse.Namespace) -> int | None:
    """Return an exit code for a command handled here, or None."""
    handlers = {"init": _init, "fix": _fix, "deslop": _deslop, "preflight": _preflight, "rule": _rule}
    handler = handlers.get(args.command)
    return handler(args) if handler is not None else None


def _init(args: argparse.Namespace) -> int:
    try:
        report = run_init(
            Path(args.path),
            install_hook=not args.no_hook,
            antigravity=args.antigravity,
            cursor=args.cursor,
            claude=args.claude,
            ci=args.ci,
            force=args.force,
        )
    except (FileNotFoundError, OSError) as exc:
        return _error(exc)
    if args.json:
        json.dump(report.to_dict(), sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        print(render_init_summary(report))
    return 0


def _fix(args: argparse.Namespace) -> int:
    root = Path(args.path).expanduser().resolve()
    if args.revert:
        try:
            restored = revert_rule(root, args.revert)
        except (CollectorError, OSError, json.JSONDecodeError) as exc:
            return _error(exc)
        print(f"Reverted {args.revert} in {len(restored)} file(s).")
        for path in restored:
            print(f"  {path}")
        return 0
    try:
        report = fix_tree(root, use_host=not args.no_host)
    except (CollectorError, OSError) as exc:
        return _error(exc)
    if args.json:
        json.dump(
            {
                "changed": list(report.changed),
                "remaining": list(report.remaining),
                "host": report.host,
                "workers": report.workers,
                "held": list(report.held),
            },
            sys.stdout,
            indent=2,
        )
        sys.stdout.write("\n")
    else:
        print(_fix_text(report))
    if args.sarif:
        write_rows_sarif(list(report.remaining), args.sarif)
    return 0 if report.clean else 1


def _fix_text(report: FixReport) -> str:
    lines = [f"Changed {len(report.changed)} file(s) on {report.workers} thread(s). Host: {report.host}."]
    for path in report.changed:
        lines.append(f"  {path}")
    if report.remaining:
        lines.append(f"Still residue: {len(report.remaining)}.")
        for item in report.remaining:
            lines.append(f"  {item}")
    else:
        lines.append("No slop residue remains.")
    if report.held:
        lines.append("Left for a person:")
        lines.extend(f"  {item}" for item in report.held)
    if report.host == "no host" and report.remaining:
        lines.append("Set VIBECLEANER_HOST to claude-code, codex, or antigravity to clean what is left.")
    return "\n".join(lines)


def _deslop(args: argparse.Namespace) -> int:
    root = Path(args.path).expanduser().resolve()
    try:
        ctx = collect(root, diff_base=args.diff_base)
        rules = load_project_rules(ctx.root)
    except (CollectorError, ProjectRulesError) as exc:
        return _error(exc)
    findings = run_deterministic(ctx) + apply_project_rules(rules, ctx.files)
    slop = [finding for finding in findings if finding.category == Category.SLOP]
    lanes = _lanes(slop, _project_lanes(rules))
    score = slop_score(slop, len(ctx.files))
    if args.json:
        payload = {
            "slop_score": score,
            "files_scanned": len(ctx.files),
            "lanes": {lane: [_finding_row(finding) for finding in items] for lane, items in lanes.items()},
        }
        json.dump(payload, sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        destination = Path(args.out) if args.out else root / "VIBECLEANER_DESLOP.md"
        try:
            destination.write_text(_deslop_markdown(lanes, score, len(ctx.files), args.diff_base), encoding="utf-8")
        except OSError as exc:
            return _error(exc)
        busy = sum(1 for items in lanes.values() if items)
        print(f"wrote {destination} (slop score {score}, {len(slop)} finding(s) in {busy} lane(s))")
    return 1 if fails_on(slop, args.fail_on) else 0


def _project_lanes(rules: ProjectRules) -> dict[str, str]:
    lanes: dict[str, str] = {}
    for rule in rules.rules:
        if isinstance(rule, PatternRule) and rule.lane is not None:
            lanes[PROJECT_RULE_PREFIX + rule.id] = rule.lane
    return lanes


def _lanes(findings: list[Finding], project_lanes: dict[str, str] | None = None) -> dict[str, list[Finding]]:
    chosen = project_lanes or {}
    lanes: dict[str, list[Finding]] = {lane: [] for lane in DESLOP_LANES}
    for finding in sorted(findings, key=lambda item: (item.file, item.line)):
        lanes.setdefault(_lane_for(finding.rule_id, chosen), []).append(finding)
    return lanes


def _lane_for(rule_id: str, project_lanes: dict[str, str]) -> str:
    """Return the cleanup lane for ``rule_id``.

    Detector ids use ``DESLOP_CONCERNS``. ``D8.*`` is ``defensive-code``.
    A project pattern uses its ``lane`` when set, otherwise ``ai-slop``.
    Any other rule id uses ``dedupe``.
    """
    mapped = DESLOP_CONCERNS.get(rule_id)
    if mapped is not None:
        return mapped
    family = _FAMILY_LANES.get(rule_id.split(".", 1)[0])
    if family is not None:
        return family
    if rule_id.startswith(PROJECT_RULE_PREFIX):
        return project_lanes.get(rule_id, DEFAULT_DESLOP_LANE)
    return "dedupe"


def _deslop_markdown(lanes: dict[str, list[Finding]], score: int, files: int, diff_base: str | None) -> str:
    scope = f"files changed since `{diff_base}`" if diff_base else "the whole tree"
    lines = [
        "# Deslop plan",
        "",
        f"Slop score {score} over {files} file(s), {scope}.",
        "",
        "Give each lane with findings to its own agent. Every lane is behavior-preserving:",
        "the tests and `vibecleaner scan` must stay green, and an edit that changes errors,",
        "side effects, ordering, or output is out of scope. Apply high-confidence changes only,",
        "keep one concern per commit, and leave auth, payments, and data-integrity code to a person",
        "when the change is not mechanical.",
        "",
    ]
    for lane in DESLOP_LANES:
        items = lanes.get(lane, [])
        lines.append(f"## {lane} ({len(items)})")
        lines.append("")
        lines.append(CONCERN_BRIEFS.get(lane, ""))
        lines.append("")
        if not items:
            lines.append("No detector findings. The agent may still research this lane but must not invent work.")
            lines.append("")
            continue
        lines.append("| Rule | Location | Message |")
        lines.append("| --- | --- | --- |")
        for finding in items:
            message = markdown_cell(finding.message)
            lines.append(f"| `{finding.rule_id}` | `{finding.file}:{finding.line}` | {message} |")
        lines.append("")
    lines.extend(
        [
            "## Before each edit",
            "",
            "Write a short equivalence note: same inputs, same return values, same errors raised,",
            "same side effects in the same order. If you cannot state it, do not make the edit.",
            "Run the tests after each lane and record what changed and how it was verified.",
            "",
        ]
    )
    return "\n".join(lines)


def _finding_row(finding: Finding) -> dict[str, object]:
    return {
        "rule_id": finding.rule_id,
        "file": finding.file,
        "line": finding.line,
        "severity": finding.severity.value,
        "message": finding.message,
    }


def _preflight(args: argparse.Namespace) -> int:
    root = Path(args.path).expanduser().resolve()
    try:
        ctx = collect(root)
        rules = load_project_rules(ctx.root)
    except (CollectorError, ProjectRulesError) as exc:
        return _error(exc)
    findings = run_deterministic(ctx) + apply_project_rules(rules, ctx.files)
    report = run_preflight(ctx, findings)
    if args.json:
        json.dump(preflight_to_json(report), sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        destination = Path(args.out) if args.out else root / "VIBECLEANER_PREFLIGHT.md"
        try:
            destination.write_text(render_preflight_markdown(report), encoding="utf-8")
        except OSError as exc:
            return _error(exc)
        counts = {status: 0 for status in Status}
        for check in report.checks:
            counts[check.status] += 1
        summary = ", ".join(f"{count} {status.value}" for status, count in counts.items() if count)
        print(f"wrote {destination} ({summary}; {len(report.blockers)} blocker(s))")
    return 1 if report.blockers else 0


def _rule(args: argparse.Namespace) -> int:
    root = Path(args.path).expanduser().resolve()
    try:
        if args.rule_command == "list":
            return _rule_list(root)
        if args.rule_command == "add-pattern":
            return _rule_add_pattern(root, args)
        return _rule_add_boundary(root, args)
    except (ProjectRulesError, CollectorError) as exc:
        return _error(exc)


def _rule_list(root: Path) -> int:
    rules = load_project_rules(root)
    if not rules.rules:
        print(f"no project rules in {root / '.vibecleaner' / 'rules.json'}")
        return 0
    for rule in rules.rules:
        hits = len(rule_hits_preview(root, rule))
        kind = "pattern" if isinstance(rule, PatternRule) else "import_boundary"
        print(f"P.{rule.id}  {kind}  {rule.severity}  {hits} hit(s)  {rule.message}")
    return 0


def _rule_add_pattern(root: Path, args: argparse.Namespace) -> int:
    candidate = PatternRule(
        id=args.rule_id,
        pattern=args.pattern,
        include=args.include or ["**"],
        exclude=args.exclude or [],
        severity=args.severity,
        category=args.category,
        message=args.message,
        remediation=args.remediation,
        learned_from=args.learned_from,
        lane=args.lane,
    )
    if args.preview:
        return _print_preview(root, candidate)
    path = add_pattern_rule(
        root,
        args.rule_id,
        args.pattern,
        args.message,
        include=args.include,
        exclude=args.exclude,
        severity=args.severity,
        category=args.category,
        remediation=args.remediation,
        learned_from=args.learned_from,
        lane=args.lane,
    )
    return _report_saved(root, path, candidate)


def _rule_add_boundary(root: Path, args: argparse.Namespace) -> int:
    candidate = BoundaryRule(
        id=args.rule_id,
        from_globs=args.from_globs,
        forbid=args.forbid,
        severity=args.severity,
        message=args.message,
        learned_from=args.learned_from,
    )
    if args.preview:
        return _print_preview(root, candidate)
    path = add_boundary_rule(
        root,
        args.rule_id,
        args.from_globs,
        args.forbid,
        args.message,
        severity=args.severity,
        learned_from=args.learned_from,
    )
    return _report_saved(root, path, candidate)


def _print_preview(root: Path, rule: PatternRule | BoundaryRule) -> int:
    hits = rule_hits_preview(root, rule)
    for hit in hits:
        print(f"{hit.file}:{hit.line}  {hit.snippet or hit.message}")
    print(f"P.{rule.id} would flag {len(hits)} line(s); not saved")
    return 0


def _report_saved(root: Path, path: Path, rule: PatternRule | BoundaryRule) -> int:
    hits = rule_hits_preview(root, rule)
    print(f"saved P.{rule.id} to {path}; it flags {len(hits)} line(s) today")
    return 0


def fails_on(findings: list[Finding], fail_on: str) -> bool:
    """True when a finding's severity is at least ``fail_on``. ``none`` never fails."""
    if fail_on == "none":
        return False
    minimum = Severity(fail_on).rank
    return any(finding.severity.rank >= minimum for finding in findings)


def _error(exc: Exception) -> int:
    print(f"error: {exc}", file=sys.stderr)
    return 2
