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
from vibecleaner.doctor import render_doctor_text, run_doctor
from vibecleaner.fix_contract import Verdict
from vibecleaner.flows import FlowsError, load_flows, run_flows
from vibecleaner.init_cmd import render_init_summary, run_init
from vibecleaner.models import PROJECT_RULE_PREFIX, Category, Finding, Severity
from vibecleaner.preflight import Status, preflight_to_json, render_preflight_markdown, run_preflight
from vibecleaner.prompt_fix import copy_to_clipboard, run_agent_fix
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
from vibecleaner.test_coverage import (
    audit_test_coverage,
    build_test_prompt,
    generate_missing_tests,
    render_coverage_markdown,
)
from vibecleaner.triage import generate_codeowners, render_triage_markdown, run_triage
from vibecleaner.verify.tamper import check_tamper, snapshot

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
    deslop.add_argument("--no-report", action="store_true", help="do not write VIBECLEANER_DESLOP.md")
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
    preflight.add_argument("--no-report", action="store_true", help="do not write VIBECLEANER_PREFLIGHT.md")
    preflight.add_argument("--json", action="store_true", help="print JSON to stdout and nothing else")

    tests = sub.add_parser("tests", help="audit test coverage/quality and generate missing test suites")
    tests.add_argument("path", nargs="?", default=".", help="repository root (default: .)")
    tests.add_argument("--diff", dest="diff_base", default=None, metavar="BASE", help="only audit files changed since BASE")
    tests.add_argument("--run-coverage", action="store_true", help="run pytest under sys.monitoring for real line coverage")
    tests.add_argument("--generate", action="store_true", help="generate missing test suites and verify them")
    tests.add_argument("--limit", type=int, default=10, metavar="N", help="maximum test files to generate (default: 10)")
    tests.add_argument("--no-verify", action="store_true", help="skip running generated tests in the sandbox")
    tests.add_argument("--keep-failing", action="store_true", help="keep generated test files even if verification fails")
    tests.add_argument("--min-score", type=int, default=0, metavar="N", help="exit 1 when coverage score is below N (0..100)")
    tests.add_argument("--fail-on", choices=_FAIL_CHOICES, default="none", help="exit 1 on coverage gaps at or above severity")
    tests.add_argument("--prompt", action="store_true", help="print the AI prompt to implement missing/weak tests")
    tests.add_argument("--copy", action="store_true", help="copy the AI test prompt to the clipboard")
    tests.add_argument("--autofix", action="store_true", help="run an AI coding agent CLI to implement missing tests")
    tests.add_argument("--agent", default=None, metavar="CMD", help="agent CLI for --autofix (claude, codex, gemini, agy, or command)")
    tests.add_argument("--max-fix-rounds", type=int, default=1, metavar="N", help="maximum --autofix rounds (1..5, default: 1)")
    tests.add_argument("--out", default=None, metavar="PATH", help="markdown report path (default: <root>/VIBECLEANER_TESTS.md)")
    tests.add_argument("--no-report", action="store_true", help="do not write VIBECLEANER_TESTS.md")
    tests.add_argument("--json", action="store_true", help="print JSON to stdout and nothing else")

    doctor = sub.add_parser("doctor", help="check Python, Git, Docker, API keys, agent CLIs, and repo config")
    doctor.add_argument("path", nargs="?", default=".", help="repository root (default: .)")
    doctor.add_argument("--json", action="store_true", help="print JSON to stdout and nothing else")

    triage = sub.add_parser("triage", help="classify modules as Keep / Fix / Rebuild and optionally generate CODEOWNERS")
    triage.add_argument("path", nargs="?", default=".", help="repository root (default: .)")
    triage.add_argument("--days", type=int, default=90, metavar="N", help="git churn lookback window in days (default: 90)")
    triage.add_argument("--out", default=None, metavar="PATH", help="markdown path (default: <root>/VIBECLEANER_TRIAGE.md)")
    triage.add_argument("--no-report", action="store_true", help="do not write VIBECLEANER_TRIAGE.md")
    triage.add_argument("--write-codeowners", default=None, metavar="OWNER", help="write .github/CODEOWNERS for high-risk paths")
    triage.add_argument("--codeowners-out", default=None, metavar="PATH", help="custom CODEOWNERS output path")
    triage.add_argument("--json", action="store_true", help="print JSON to stdout and nothing else")

    flows = sub.add_parser("flows", help="run money-path / critical-flow verification specs (.vibecleaner/flows.json)")
    flows.add_argument("path", nargs="?", default=".", help="repository root (default: .)")
    flows.add_argument("--file", dest="flows_file", default=None, metavar="PATH", help="custom flows.json path")
    flows.add_argument("--json", action="store_true", help="print JSON to stdout and nothing else")

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
    handlers = {
        "init": _init,
        "fix": _fix,
        "deslop": _deslop,
        "preflight": _preflight,
        "tests": _tests,
        "doctor": _doctor,
        "triage": _triage,
        "flows": _flows,
        "rule": _rule,
    }
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
        busy = sum(1 for items in lanes.values() if items)
        if getattr(args, "no_report", False):
            print(f"deslop: slop score {score}, {len(slop)} finding(s) in {busy} lane(s)")
        else:
            destination = Path(args.out) if args.out else root / "VIBECLEANER_DESLOP.md"
            try:
                destination.write_text(_deslop_markdown(lanes, score, len(ctx.files), args.diff_base), encoding="utf-8")
            except OSError as exc:
                return _error(exc)
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
        counts = {status: 0 for status in Status}
        for check in report.checks:
            counts[check.status] += 1
        summary = ", ".join(f"{count} {status.value}" for status, count in counts.items() if count)
        if getattr(args, "no_report", False):
            print(f"preflight: {summary}; {len(report.blockers)} blocker(s)")
        else:
            destination = Path(args.out) if args.out else root / "VIBECLEANER_PREFLIGHT.md"
            try:
                destination.write_text(render_preflight_markdown(report), encoding="utf-8")
            except OSError as exc:
                return _error(exc)
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


def _tests(args: argparse.Namespace) -> int:
    if not 0 <= args.min_score <= 100:
        return _error(ValueError("--min-score must be between 0 and 100"))
    if args.limit < 1:
        return _error(ValueError("--limit must be at least 1"))
    if not 1 <= args.max_fix_rounds <= 5:
        return _error(ValueError("--max-fix-rounds must be between 1 and 5"))

    root = Path(args.path).expanduser().resolve()
    try:
        report = audit_test_coverage(root, diff_base=args.diff_base, run_coverage=args.run_coverage)
    except (CollectorError, OSError) as exc:
        return _error(exc)

    generation = None
    if args.generate and report.gaps:
        generation = generate_missing_tests(
            report,
            limit=args.limit,
            verify=not args.no_verify,
            keep_failing=args.keep_failing,
        )
        if generation.tamper_blocked:
            return _error(RuntimeError(f"test generation aborted due to tampering: {generation.tamper_detail}"))
        if generation.created_count > 0:
            report = audit_test_coverage(root, diff_base=args.diff_base, run_coverage=args.run_coverage)

    if args.autofix and report.gaps:
        autofix_code, report = _tests_autofix_loop(root, report, args)
        if autofix_code is not None:
            return autofix_code

    write_report = not args.no_report and not args.json and not args.prompt
    destination: Path | None = None
    if write_report:
        destination = Path(args.out) if args.out else root / "VIBECLEANER_TESTS.md"
        try:
            destination.write_text(render_coverage_markdown(report, generation), encoding="utf-8")
        except OSError as exc:
            return _error(exc)

    if args.json:
        payload = report.to_dict()
        if generation is not None:
            payload["generation"] = generation.to_dict()
        json.dump(payload, sys.stdout, indent=2)
        sys.stdout.write("\n")
    elif args.prompt:
        prompt = build_test_prompt(report)
        if prompt:
            print(prompt)
    else:
        dest_note = f" (wrote {destination})" if destination is not None else ""
        print(
            f"Test coverage score: {report.coverage_score}/100 "
            f"({report.tested_modules}/{report.total_modules} modules, "
            f"{report.tested_symbols}/{report.total_symbols} symbols, "
            f"{len(report.gaps)} gap(s)){dest_note}"
        )
        if generation is not None and generation.results:
            print(
                f"Generated {generation.created_count} test file(s), "
                f"{generation.verified_count} verified passing."
            )

    if args.copy and report.gaps:
        prompt = build_test_prompt(report)
        copied, info = copy_to_clipboard(prompt)
        if copied:
            print(f"Copied test prompt to clipboard via {info}.", file=sys.stderr)
        else:
            print(f"warning: could not copy test prompt ({info})", file=sys.stderr)

    if args.min_score > 0 and report.coverage_score < args.min_score:
        return 1
    if _gaps_fail_on(report.gaps, args.fail_on):
        return 1
    return 0


def _tests_autofix_loop(root: Path, report, args: argparse.Namespace):
    stream = sys.stderr if (args.json or args.prompt) else sys.stdout
    current = report
    for round_num in range(1, args.max_fix_rounds + 1):
        prompt = build_test_prompt(current)
        if not prompt:
            return None, current
        before_score = current.coverage_score
        before = snapshot(root)
        outcome = run_agent_fix(root, prompt, agent=args.agent)
        print(outcome.detail, file=stream)
        if outcome.status == "failed":
            return 2, current
        if outcome.status in {"copied", "no_agent"}:
            return None, current
        tamper = check_tamper(before, root)
        if tamper.verdict is Verdict.REVISE:
            details = "; ".join(item.summary for item in tamper.evidence)
            print(f"error: --autofix aborted due to test/config tampering: {details}", file=sys.stderr)
            return 2, current
        current = audit_test_coverage(root, diff_base=args.diff_base, run_coverage=args.run_coverage)
        print(
            f"VIBECLEANER TESTS AUTOFIX round {round_num}: score {before_score} -> {current.coverage_score}",
            file=stream,
        )
        if not current.gaps or (args.min_score > 0 and current.coverage_score >= args.min_score):
            return None, current
    return None, current


def _gaps_fail_on(gaps, fail_on: str) -> bool:
    if fail_on == "none":
        return False
    minimum = Severity(fail_on).rank
    return any(gap.severity.rank >= minimum for gap in gaps)


def _doctor(args: argparse.Namespace) -> int:
    report = run_doctor(Path(args.path))
    if args.json:
        json.dump(report.to_dict(), sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        print(render_doctor_text(report))
    return 1 if report.has_errors else 0


def _triage(args: argparse.Namespace) -> int:
    if args.days < 1:
        return _error(ValueError("--days must be at least 1"))
    root = Path(args.path).expanduser().resolve()
    try:
        report = run_triage(root, days=args.days)
    except (CollectorError, OSError) as exc:
        return _error(exc)
    codeowners_path: Path | None = None
    if args.write_codeowners is not None:
        try:
            text = generate_codeowners(report, args.write_codeowners)
            codeowners_path = Path(args.codeowners_out) if args.codeowners_out else root / ".github" / "CODEOWNERS"
            codeowners_path.parent.mkdir(parents=True, exist_ok=True)
            codeowners_path.write_text(text, encoding="utf-8")
        except (ValueError, OSError) as exc:
            return _error(exc)
    destination: Path | None = None
    if not args.no_report and not args.json:
        destination = Path(args.out) if args.out else root / "VIBECLEANER_TRIAGE.md"
        try:
            destination.write_text(render_triage_markdown(report), encoding="utf-8")
        except OSError as exc:
            return _error(exc)
    if args.json:
        payload = report.to_dict()
        if codeowners_path is not None:
            payload["codeowners_path"] = str(codeowners_path)
        json.dump(payload, sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        counts = report.counts
        extra = f" (wrote {destination})" if destination is not None else ""
        print(
            f"Triage: rebuild={counts['rebuild']}, fix={counts['fix']}, keep={counts['keep']}, "
            f"high_risk={len(report.high_risk_paths)}{extra}"
        )
        if codeowners_path is not None:
            print(f"Wrote CODEOWNERS to {codeowners_path}")
    return 0


def _flows(args: argparse.Namespace) -> int:
    root = Path(args.path).expanduser().resolve()
    custom = Path(args.flows_file) if args.flows_file else None
    try:
        specs = load_flows(root, custom)
    except FlowsError as exc:
        return _error(exc)
    if not specs:
        if args.json:
            json.dump({"root": str(root), "ok": True, "passed": 0, "failed": 0, "results": []}, sys.stdout, indent=2)
            sys.stdout.write("\n")
        else:
            print("No flows configured (.vibecleaner/flows.json not found).")
        return 0
    report = run_flows(root, specs)
    if args.json:
        json.dump(report.to_dict(), sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        for item in report.results:
            tag = "PASS" if item.ok else "FAIL"
            print(f"[{tag}] {item.name} ({item.kind}, {item.duration_s:.2f}s): {item.detail}")
        print(f"Flows: {report.passed}/{len(report.results)} passed")
    return 0 if report.ok else 1
