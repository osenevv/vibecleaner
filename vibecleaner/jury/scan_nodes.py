"""Static scan, security, validation, and maintainability nodes."""

from __future__ import annotations

from vibecleaner.fix_contract import CheckResult, Evidence, EvidenceKind, FixContext, Verdict
from vibecleaner.models import Category, Finding, ScanResult, Severity
from vibecleaner.pipeline import run_scan

_VALIDATION = frozenset({"D7a.n_plus_one_loop", "D7b.missing_boundary_schema"})


class ScanLedger:
    """One graph run's scan, filled by the static node and read by the later free nodes."""

    def __init__(self) -> None:
        self.result: ScanResult | None = None
        self.command: tuple[str, ...] = ()


def run_static(ctx: FixContext, ledger: ScanLedger) -> CheckResult:
    command = _scan_command(ctx)
    ledger.command = command
    result, _scan_ctx = run_scan(
        ctx.root,
        diff_base=ctx.base_ref,
        mode="offline",
        use_cache=False,
        fix=False,
    )
    ledger.result = result
    if result.judge.errors:
        raise RuntimeError("offline scan reported judge errors: " + "; ".join(result.judge.errors))
    findings = _at_least(result, Severity.HIGH)
    return _verdict("static_scan", findings, command)


def run_security(ledger: ScanLedger) -> CheckResult:
    findings = [
        finding
        for finding in _at_least(_require(ledger), Severity.HIGH)
        if finding.category is Category.SECURITY
    ]
    return _verdict("security", findings, ledger.command)


def run_validation(ledger: ScanLedger) -> CheckResult:
    findings = [
        finding
        for finding in _require(ledger).findings
        if finding.rule_id in _VALIDATION and finding.severity.rank >= Severity.MEDIUM.rank
    ]
    return _verdict("validation", findings, ledger.command)


def run_maintainability(ctx: FixContext, ledger: ScanLedger) -> CheckResult:
    findings = [
        finding
        for finding in _require(ledger).findings
        if finding.category is Category.SLOP and finding.severity.rank >= Severity.MEDIUM.rank
        and finding.rule_id not in _VALIDATION
    ]
    command = ("vibecleaner", "deslop", str(ctx.root), "--fail-on", "medium")
    return _verdict("maintainability", findings, command)


def _scan_command(ctx: FixContext) -> tuple[str, ...]:
    command = ["vibecleaner", "scan", str(ctx.root), "--mode", "offline", "--no-cache"]
    if ctx.base_ref:
        command.extend(["--diff", ctx.base_ref])
    return tuple(command)


def _require(ledger: ScanLedger) -> ScanResult:
    if ledger.result is None:
        raise RuntimeError("static scan did not run")
    return ledger.result


def _at_least(result: ScanResult, minimum: Severity) -> list[Finding]:
    return [finding for finding in result.findings if finding.severity.rank >= minimum.rank]


def _verdict(node: str, findings: list[Finding], command: tuple[str, ...]) -> CheckResult:
    if not findings:
        return CheckResult(node, Verdict.PASS)
    evidence = tuple(
        Evidence(
            EvidenceKind.STATIC,
            f"{finding.file}:{finding.line} {finding.message}",
            file=finding.file,
            line=finding.line,
            command=command,
            output=finding.message,
        )
        for finding in findings[:12]
    )
    return CheckResult(node, Verdict.REVISE, evidence=evidence)
