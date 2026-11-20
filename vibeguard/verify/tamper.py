"""Compare a tree with the snapshot taken before a fix."""

from __future__ import annotations

from pathlib import Path

from vibeguard.fix_contract import CheckResult, Verdict
from vibeguard.verify.checks import collect_findings
from vibeguard.verify.snapshot import TamperSnapshot, snapshot

__all__ = ["TamperSnapshot", "check_tamper", "snapshot"]


def check_tamper(
    before: TamperSnapshot,
    tree: Path,
    *,
    allowed_signatures: frozenset[str] = frozenset(),
) -> CheckResult:
    after = snapshot(tree)
    findings = collect_findings(before, after, allowed_signatures)
    if not findings:
        return CheckResult(node="tamper_guard", verdict=Verdict.PASS)
    ordered = tuple(sorted(findings, key=lambda item: (item.file or "", item.line or 0, item.summary)))
    return CheckResult(node="tamper_guard", verdict=Verdict.REVISE, evidence=ordered)
