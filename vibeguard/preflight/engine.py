"""Run the 42 launch checks in order."""

from __future__ import annotations

from collections.abc import Callable

from vibeguard.models import Finding, ScanContext

from vibeguard.preflight.results import (
    CheckResult,
    PreflightReport,
    Status,
    _blockers,
    _can_wait,
    _first_actions,
)
from vibeguard.preflight.section_a import check_01, check_02, check_03, check_04, check_05
from vibeguard.preflight.section_b import (
    check_06,
    check_07,
    check_08,
    check_09,
    check_10,
    check_11,
    check_12,
    check_13,
    check_14,
    check_15,
    check_16,
    check_17,
)
from vibeguard.preflight.section_c import (
    check_18,
    check_19,
    check_20,
    check_21,
    check_22,
    check_23,
    check_24,
)
from vibeguard.preflight.section_d import (
    check_25,
    check_26,
    check_27,
    check_28,
    check_29,
    check_30,
    check_31,
)
from vibeguard.preflight.section_e import (
    check_32,
    check_33,
    check_34,
    check_35,
    check_36,
    check_37,
    check_38,
    check_39,
    check_40,
    check_41,
    check_42,
)
from vibeguard.preflight.signals import detect_stack, infer_summary
from vibeguard.preflight.view import RepoView


_EVALUATORS: tuple[Callable[[RepoView], CheckResult], ...] = (
    check_01,
    check_02,
    check_03,
    check_04,
    check_05,
    check_06,
    check_07,
    check_08,
    check_09,
    check_10,
    check_11,
    check_12,
    check_13,
    check_14,
    check_15,
    check_16,
    check_17,
    check_18,
    check_19,
    check_20,
    check_21,
    check_22,
    check_23,
    check_24,
    check_25,
    check_26,
    check_27,
    check_28,
    check_29,
    check_30,
    check_31,
    check_32,
    check_33,
    check_34,
    check_35,
    check_36,
    check_37,
    check_38,
    check_39,
    check_40,
    check_41,
    check_42,
)


def run_preflight(ctx: ScanContext, findings: list[Finding]) -> PreflightReport:
    """Answer the 42 launch checks from ``ctx`` and findings the caller already computed."""
    view = RepoView(ctx, findings)
    checks = [evaluator(view) for evaluator in _EVALUATORS]
    ids = [check.id for check in checks]
    if ids != list(range(1, 43)):
        raise RuntimeError(f"preflight checks must be 1..42 in order, got {ids}")
    for check in checks:
        if check.status == Status.NOT_CHECKED and not check.verify.strip():
            raise RuntimeError(f"check {check.id} is Not checked without verify instructions")
    blockers = _blockers(checks)
    return PreflightReport(
        summary=infer_summary(view),
        stack=detect_stack(view),
        checks=checks,
        blockers=blockers,
        can_wait=_can_wait(checks),
        first_actions=_first_actions(checks, blockers),
    )
