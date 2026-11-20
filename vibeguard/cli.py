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
from vibeguard.decision_judge import DecisionAPIError
from vibeguard.models import DEFAULT_THRESHOLD, Finding
from vibeguard.pipeline import run_scan
from vibeguard.reporter import render_terminal, to_json, write_markdown, write_sarif

_FAIL_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


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


def _main(argv: list[str]) -> int:
    logging.basicConfig(
        level=logging.WARNING,
        stream=sys.stderr,
        format="%(levelname)s %(name)s: %(message)s",
    )
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "version":
        print(__version__)
        return 0
    if not math.isfinite(args.threshold) or not 0.0 <= args.threshold <= 1.0:
        print("error: --threshold must be between 0 and 1", file=sys.stderr)
        return 2
    if args.no_report and args.report:
        print("error: pass only one of --report and --no-report", file=sys.stderr)
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
    except (DecisionAPIError, CollectorError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    report_explicit = args.report is not None
    write_report = not args.no_report and (report_explicit or not args.quiet)
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
    else:
        render_terminal(result, Console(highlight=False, soft_wrap=args.quiet), quiet=args.quiet)
    if result.judge.errors:
        return 2
    if _should_fail(result.findings, args.fail_on):
        return 1
    return 0


def _build_parser() -> _Parser:
    parser = _Parser(prog="vibeguard", description="Audit an AI-generated repo for security holes and code slop.")
    sub = parser.add_subparsers(dest="command", required=True)
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
    sub.add_parser("version", help="print the version")
    return parser


def _should_fail(findings: list[Finding], fail_on: str) -> bool:
    if fail_on == "none":
        return False
    minimum = _FAIL_RANK[fail_on]
    return any(finding.severity.rank >= minimum for finding in findings)


if __name__ == "__main__":
    raise SystemExit(main())
