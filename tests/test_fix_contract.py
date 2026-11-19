"""The fixer contract refuses verdicts and results that break the design rule."""

from __future__ import annotations

from pathlib import Path

import pytest

from vibecleaner.fix_contract import (
    Capabilities,
    CheckResult,
    Evidence,
    EvidenceKind,
    ExecResult,
    MAX_EVIDENCE_OUTPUT,
    Role,
    RunOutcome,
    RunResult,
    Team,
    Verdict,
)


def _failing_test() -> Evidence:
    return Evidence(EvidenceKind.TEST_FAILURE, "test_refund fails", command=("pytest", "tests/test_refund.py"))


def test_revise_without_reproduction_is_rejected() -> None:
    note = Evidence(EvidenceKind.STATIC, "looks racy")
    with pytest.raises(ValueError, match="reproducible evidence"):
        CheckResult("races", Verdict.REVISE, evidence=(note,))


def test_judge_note_cannot_be_blocking_evidence() -> None:
    with pytest.raises(ValueError, match="notes"):
        CheckResult("races", Verdict.PASS, evidence=(Evidence(EvidenceKind.JUDGE_NOTE, "maybe"),))
    with pytest.raises(ValueError, match="opinion"):
        Evidence(EvidenceKind.JUDGE_NOTE, "maybe", command=("pytest",))


def test_revise_with_reproduction_blocks() -> None:
    result = CheckResult("tests", Verdict.REVISE, evidence=(_failing_test(),))
    assert result.blocks
    assert not CheckResult("tests", Verdict.PASS).blocks


def test_long_output_is_clipped_keeping_head_and_tail() -> None:
    text = "HEAD" + "x" * (MAX_EVIDENCE_OUTPUT * 3) + "TAIL"
    evidence = Evidence(EvidenceKind.BUILD_ERROR, "build", output=text)
    assert len(evidence.output) <= MAX_EVIDENCE_OUTPUT
    assert evidence.output.startswith("HEAD") and evidence.output.endswith("TAIL")


def test_run_result_states() -> None:
    RunResult(RunOutcome.READY, "clean")
    RunResult(RunOutcome.FIXED, "fixed 1", branch="vibecleaner/fix-1", commits=("abc123",))
    RunResult(RunOutcome.NEEDS_YOU, "payments", questions=("Approve the refund change?",))
    with pytest.raises(ValueError):
        RunResult(RunOutcome.READY, "x", commits=("abc",))
    with pytest.raises(ValueError):
        RunResult(RunOutcome.FIXED, "x")
    with pytest.raises(ValueError):
        RunResult(RunOutcome.NEEDS_YOU, "x")


class _Provider:
    def __init__(self, name: str, capabilities: Capabilities) -> None:
        self.name = name
        self.family = "local:test"
        self.local = True
        self.capabilities = capabilities

    def complete(self, system: str, prompt: str, *, json_mode: bool = False) -> str:
        return "{}"

    def yes_probability(self, system: str, prompt: str) -> float | None:
        return None


class _Host:
    name = "claude-code"
    family = "anthropic"

    def run_task(self, worktree: Path, instructions: str, *, timeout_s: float) -> ExecResult:
        return ExecResult(("true",), 0, "", "", 0.0)


def test_team_assigns_roles_by_capability() -> None:
    small = _Provider("small", Capabilities(context_tokens=8_000))
    vision = _Provider("vision", Capabilities(context_tokens=32_000, tool_calls=True, vision=True))
    team = Team(host=None, providers=(small, vision))
    assert team.for_role(Role.JUDGE) == (small, vision)
    assert team.for_role(Role.PATCHER) == (vision,)
    assert team.for_role(Role.BROWSER) == (vision,)
    assert team.can_fix
    assert not Team(host=None, providers=(small,)).can_fix
    assert Team(host=_Host()).can_fix
