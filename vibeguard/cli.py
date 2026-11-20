"""``vibeguard`` command line."""

from __future__ import annotations

import argparse
import json
import logging
import math
import sys
from pathlib import Path

from rich.console import Console

from vibeguard import __version__
from vibeguard.collector import CollectorError
from vibeguard.commands import add_subcommands, fails_on, run_subcommand
from vibeguard.decision_judge import DecisionAPIError
from vibeguard.fix_contract import Verdict
from vibeguard.models import DEFAULT_THRESHOLD
from vibeguard.pipeline import run_scan
from vibeguard.project_rules import ProjectRulesError
from vibeguard.prompt_fix import build_fix_prompt, copy_to_clipboard, run_agent_fix
from vibeguard.reporter import render_terminal, to_json, write_markdown, write_sarif
from vibeguard.states import detect_state_bugs, extract_machines, render_states
from vibeguard.verify.tamper import check_tamper, snapshot


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        self.print_usage(sys.stderr)
        print(f"error: {message}", file=sys.stderr)
        raise SystemExit(2)


def main(argv: list[str] | None = None) -> int:
    """Run the CLI and return a process exit code (0 pass, 1 findings, 2 error)."""
    try:
        return _main(sys.argv[1:] if argv is None else list(argv))
    except SystemExit as exc:
        code = exc.code
        if code is None:
            return 0
        return code if isinstance(code, int) else 2


_KNOWN_COMMANDS = frozenset(
    {"scan", "start", "fix", "run", "init", "deslop", "preflight", "states", "rule", "version"}
)
_START_ALIASES = frozenset({"start", "fix", "run"})


def _normalize_argv(argv: list[str]) -> list[str]:
    if not argv:
        return ["scan"]
    first = argv[0]
    if first in {"fix", "run"}:
        return ["start", *argv[1:]]
    if first in _KNOWN_COMMANDS or first in {"-h", "--help"}:
        return argv
    if (
        first.startswith("-")
        or first in {".", ".."}
        or "/" in first
        or "\\" in first
        or Path(first).expanduser().exists()
    ):
        return ["scan", *argv]
    return argv


def _main(argv: list[str]) -> int:
    logging.basicConfig(
        level=logging.WARNING,
        stream=sys.stderr,
        format="%(levelname)s %(name)s: %(message)s",
    )
    parser = _build_parser()
    args = parser.parse_args(_normalize_argv(argv))
    if args.command == "version":
        print(__version__)
        return 0
    if args.command == "states":
        return _states(args)
    if args.command in _START_ALIASES:
        return _start(args)
    handled = run_subcommand(args)
    if handled is not None:
        return handled
    if not math.isfinite(args.threshold) or not 0.01 <= args.threshold <= 0.99:
        print(
            "error: --threshold must be between 0.01 and 0.99 "
            "(noul never returns 0 or 1, so a cutoff outside that range cannot fail the scan)",
            file=sys.stderr,
        )
        return 2
    if args.no_report and args.report:
        print("error: pass only one of --report and --no-report", file=sys.stderr)
        return 2
    if not 1 <= args.max_fix_rounds <= 5:
        print("error: --max-fix-rounds must be between 1 and 5", file=sys.stderr)
        return 2
    root = Path(args.path).expanduser().resolve()
    try:
        result, _ctx = run_scan(
            root,
            diff_base=args.diff_base,
            mode=args.mode,
            threshold=args.threshold,
            use_cache=not args.no_cache,
            fix=args.fix,
        )
    except (DecisionAPIError, CollectorError, ProjectRulesError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.autofix and not result.judge.errors and fails_on(result.findings, args.fail_on):
        autofix_code, result = _autofix_loop(root, result, args)
        if autofix_code is not None:
            return autofix_code
    report_explicit = args.report is not None
    write_report = not args.no_report and (report_explicit or (not args.quiet and not args.prompt))
    try:
        if write_report:
            report_path = Path(args.report) if report_explicit else Path(result.root) / "VIBEGUARD_REPORT.md"
            write_markdown(result, report_path)
        if args.sarif:
            write_sarif(result, args.sarif)
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.json:
        json.dump(to_json(result), sys.stdout, indent=2)
        sys.stdout.write("\n")
    elif args.prompt:
        prompt = build_fix_prompt(result, fail_on=args.fail_on)
        if prompt:
            print(prompt)
    else:
        render_terminal(result, Console(highlight=False, soft_wrap=args.quiet), quiet=args.quiet)
    if args.copy and result.findings:
        prompt = build_fix_prompt(result, fail_on=args.fail_on)
        copied, info = copy_to_clipboard(prompt)
        if copied:
            print(f"Copied fix prompt to clipboard via {info}.", file=sys.stderr)
        else:
            print(f"warning: could not copy fix prompt ({info})", file=sys.stderr)
    if result.judge.errors:
        return 2
    if fails_on(result.findings, args.fail_on):
        return 1
    return 0


def _autofix_loop(root: Path, result, args: argparse.Namespace):
    stream = sys.stderr if (args.json or args.prompt) else sys.stdout
    current = result
    for round_num in range(1, args.max_fix_rounds + 1):
        prompt = build_fix_prompt(current, fail_on=args.fail_on)
        if not prompt:
            return None, current
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
        try:
            current, _ctx = run_scan(
                root,
                diff_base=args.diff_base,
                mode=args.mode,
                threshold=args.threshold,
                use_cache=False,
                fix=args.fix,
            )
        except (DecisionAPIError, CollectorError, ProjectRulesError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2, current
        if current.judge.errors:
            return None, current
        if not fails_on(current.findings, args.fail_on):
            print(f"VIBEGUARD AUTOFIX: FIXED in {round_num} round(s)", file=stream)
            return None, current
    return None, current


def _build_parser() -> _Parser:
    parser = _Parser(
        prog="vibeguard",
        description="Audit an AI-generated repo for security holes and code slop. Bare 'vibeguard' runs 'vibeguard scan .'.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    start_cmd = sub.add_parser("start", help="check a repository and report ready, fixed, or a question")
    start_cmd.add_argument("path", nargs="?", default=".", help="repository root (default: .)")
    start_cmd.add_argument("--sandbox", choices=("docker", "host"), default="docker")
    start_cmd.add_argument("--local", action="store_true", help="use only a local model")
    start_cmd.add_argument("--no-local", action="store_true", help="do not look for a local model")
    start_cmd.add_argument("--spec", default=None, metavar="FILE")
    start_cmd.add_argument("--base", default=None, metavar="REF")
    start_cmd.add_argument("--json", action="store_true")
    scan = sub.add_parser("scan", help="scan a repository")
    scan.add_argument("path", nargs="?", default=".", help="repository root (default: .)")
    scan.add_argument("--diff", dest="diff_base", default=None, metavar="BASE", help="only scan files changed since BASE")
    scan.add_argument("--fix", action="store_true", help="draft unified diffs for critical findings")
    scan.add_argument("--mode", choices=("auto", "live", "offline", "off"), default="auto")
    scan.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD)
    scan.add_argument("--report", default=None, metavar="PATH", help="markdown report path")
    scan.add_argument("--no-report", action="store_true", help="do not write VIBEGUARD_REPORT.md")
    scan.add_argument("--sarif", default=None, metavar="PATH")
    scan.add_argument("--json", action="store_true", help="print JSON to stdout and nothing else")
    scan.add_argument(
        "--quiet",
        action="store_true",
        help="print only 'VIBEGUARD: PASS' on pass; one line per finding otherwise",
    )
    scan.add_argument(
        "--fail-on",
        choices=("critical", "high", "medium", "low", "none"),
        default="high",
        help="exit 1 when a finding is at or above this severity (default: high)",
    )
    scan.add_argument("--no-cache", action="store_true")
    scan.add_argument("--prompt", action="store_true", help="print only the plain-English AI fix prompt")
    scan.add_argument("--copy", action="store_true", help="copy the AI fix prompt to the system clipboard")
    scan.add_argument(
        "--autofix",
        action="store_true",
        help="hand the fix prompt to an installed AI coding agent CLI (or clipboard) and re-scan",
    )
    scan.add_argument(
        "--agent",
        default=None,
        metavar="CMD",
        help="agent CLI for --autofix (claude, codex, gemini, agy, or custom command)",
    )
    scan.add_argument(
        "--max-fix-rounds",
        type=int,
        default=1,
        metavar="N",
        help="maximum --autofix agent + re-scan rounds (1..5, default: 1)",
    )
    states = sub.add_parser("states", help="write state machines and confirmed invalid transitions")
    states.add_argument("path", nargs="?", default=".", help="repository root (default: .)")
    states.add_argument("--out", default=None, metavar="PATH", help="markdown path (default: <root>/VIBEGUARD_STATES.md)")
    states.add_argument(
        "--fail-on",
        choices=("critical", "high", "medium", "low", "none"),
        default="high",
        help="exit 1 when a confirmed transition is at or above this severity",
    )
    add_subcommands(sub)
    sub.add_parser("version", help="print the version")
    return parser


def _start(args: argparse.Namespace) -> int:
    from vibeguard.run import RunOptions, start
    from vibeguard.run.loop import exit_code

    if args.local and args.no_local:
        print("error: pass only one of --local and --no-local", file=sys.stderr)
        return 2
    local = True if args.local else False if args.no_local else None
    root = Path(args.path).expanduser().resolve()
    options = RunOptions(
        base_ref=args.base,
        spec_path=Path(args.spec) if args.spec else None,
        local=local,
        sandbox=args.sandbox,
    )
    try:
        result = start(root, options, lambda line: None if args.json else print(line))
    except (FileNotFoundError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.json:
        json.dump(
            {
                "outcome": result.outcome.value,
                "summary": result.summary,
                "questions": list(result.questions),
            },
            sys.stdout,
            indent=2,
        )
        sys.stdout.write("\n")
    else:
        print(result.summary)
        for question in result.questions:
            print(question)
    return exit_code(result)


def _states(args: argparse.Namespace) -> int:
    from vibeguard.collector import collect

    root = Path(args.path).expanduser().resolve()
    try:
        ctx = collect(root)
    except CollectorError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    machines = extract_machines(ctx.files)
    findings = [finding for source in ctx.files for finding in detect_state_bugs(source)]
    destination = Path(args.out) if args.out else root / "VIBEGUARD_STATES.md"
    try:
        destination.write_text(render_states(machines, findings), encoding="utf-8")
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"wrote {destination} ({len(machines)} machine(s), {len(findings)} invalid transition(s))")
    if fails_on(findings, args.fail_on):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
