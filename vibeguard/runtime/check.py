"""Runtime check. A library skips the port. A detected server is not called a pass."""

from __future__ import annotations

from pathlib import Path

from vibeguard.fix_contract import CheckResult, Evidence, EvidenceKind, FixContext, Verdict
from vibeguard.runtime.detect import detect_app


def runtime_check(ctx: FixContext, cwd: Path) -> CheckResult:
    """Return a pass when nothing serves HTTP, and escalate when a server was found."""
    del ctx
    root = Path(cwd)
    spec = detect_app(root)
    if spec is None:
        return CheckResult(
            "runtime",
            Verdict.PASS,
            notes=(Evidence(EvidenceKind.JUDGE_NOTE, "No web app to boot."),),
        )
    command = " ".join(spec.command(8765))
    return CheckResult(
        "runtime",
        Verdict.ESCALATE,
        notes=(
            Evidence(
                EvidenceKind.JUDGE_NOTE,
                f"A {spec.kind} app was detected and was not booted. Command: {command}",
            ),
        ),
    )
