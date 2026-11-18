"""Shared contract for the fixer that bare `vibecleaner` runs.

`verify/`, `probes/`, `runtime/`, `agents/`, `repair/`, `jury/` and `run/` only
exchange the types defined here and in `models.py`. A blocking verdict must
carry reproducible evidence; the constructors below refuse anything else.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Protocol

MAX_EVIDENCE_OUTPUT = 4000


def clip(text: str, limit: int = MAX_EVIDENCE_OUTPUT) -> str:
    """Keep the head and tail of long tool output, where errors usually are."""
    if len(text) <= limit:
        return text
    half = (limit - 40) // 2
    return f"{text[:half]}\n... [{len(text) - 2 * half} characters cut] ...\n{text[-half:]}"


class EvidenceKind(str, Enum):
    STATIC = "static"
    BUILD_ERROR = "build_error"
    TYPE_ERROR = "type_error"
    LINT_ERROR = "lint_error"
    TEST_FAILURE = "test_failure"
    TAMPER = "tamper"
    COUNTEREXAMPLE = "counterexample"
    SURVIVING_MUTANT = "surviving_mutant"
    DIVERGENCE = "divergence"
    RUNTIME_TRACE = "runtime_trace"
    INTERACTION = "interaction"
    JUDGE_NOTE = "judge_note"


@dataclass(frozen=True)
class Evidence:
    """Something observed. ``command`` reproduces it; a judge note has none."""

    kind: EvidenceKind
    summary: str
    file: str | None = None
    line: int | None = None
    command: tuple[str, ...] = ()
    output: str = ""
    reproducer: str | None = None

    def __post_init__(self) -> None:
        if self.kind is EvidenceKind.JUDGE_NOTE and self.command:
            raise ValueError("a judge note is an opinion; give it no reproduction command")
        if len(self.output) > MAX_EVIDENCE_OUTPUT:
            object.__setattr__(self, "output", clip(self.output))

    @property
    def reproducible(self) -> bool:
        return bool(self.command)


class Verdict(str, Enum):
    PASS = "pass"
    REVISE = "revise"
    ESCALATE = "escalate"
    RETHINK_DESIGN = "rethink_design"


class CostClass(str, Enum):
    FREE = "free"
    EXECUTION = "execution"
    MODEL = "model"


@dataclass(frozen=True)
class CheckResult:
    node: str
    verdict: Verdict
    evidence: tuple[Evidence, ...] = ()
    notes: tuple[Evidence, ...] = ()

    def __post_init__(self) -> None:
        if self.verdict is Verdict.REVISE and not any(item.reproducible for item in self.evidence):
            raise ValueError(f"{self.node}: a blocking verdict needs reproducible evidence")
        if any(item.kind is EvidenceKind.JUDGE_NOTE for item in self.evidence):
            raise ValueError(f"{self.node}: judge notes belong in notes, not evidence")

    @property
    def blocks(self) -> bool:
        return self.verdict is not Verdict.PASS


@dataclass(frozen=True)
class ExecResult:
    command: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    duration_s: float
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


class SandboxUnavailable(RuntimeError):
    """Docker (or the requested sandbox) cannot run project code."""


class Sandbox(Protocol):
    """Runs project code. ``cwd`` is an absolute path inside the project root.

    Worktrees live under ``<root>/.vibecleaner/worktrees/`` so one mount covers them.
    """

    name: str
    root: Path

    def run(
        self,
        command: Sequence[str],
        *,
        cwd: Path,
        timeout_s: float,
        network: bool = False,
        env: Mapping[str, str] | None = None,
    ) -> ExecResult: ...


class Role(str, Enum):
    JUDGE = "judge"
    PATCHER = "patcher"
    TESTER = "tester"
    BROWSER = "browser"


@dataclass(frozen=True)
class Capabilities:
    context_tokens: int
    tool_calls: bool = False
    vision: bool = False
    logprobs: bool = False

    def meets(self, minimum: Capabilities) -> bool:
        return (
            self.context_tokens >= minimum.context_tokens
            and (self.tool_calls or not minimum.tool_calls)
            and (self.vision or not minimum.vision)
        )


ROLE_MINIMUMS: Mapping[Role, Capabilities] = {
    Role.JUDGE: Capabilities(context_tokens=8_000),
    Role.PATCHER: Capabilities(context_tokens=16_000),
    Role.TESTER: Capabilities(context_tokens=8_000),
    Role.BROWSER: Capabilities(context_tokens=16_000, tool_calls=True, vision=True),
}


class ProviderError(RuntimeError):
    """A model call failed; the caller decides whether another provider can take the role."""


class Provider(Protocol):
    """One chat model behind an API or a local server."""

    name: str  # e.g. "ollama:qwen2.5-coder:14b"
    family: str  # "gemini" | "anthropic" | "openai" | "local:<model family>"
    local: bool
    capabilities: Capabilities

    def complete(self, system: str, prompt: str, *, json_mode: bool = False) -> str: ...

    def yes_probability(self, system: str, prompt: str) -> float | None:
        """P(yes) for a constrained yes/no answer, or None when the backend has no log-probabilities."""
        ...


class AgentHost(Protocol):
    """A coding agent that edits files itself (Claude Code, Codex, Antigravity)."""

    name: str  # "claude-code" | "codex" | "antigravity"
    family: str  # "anthropic" | "openai" | "gemini"

    def run_task(self, worktree: Path, instructions: str, *, timeout_s: float) -> ExecResult: ...


@dataclass(frozen=True)
class Team:
    """Who writes patches and who judges them for one run."""

    host: AgentHost | None
    providers: tuple[Provider, ...] = ()

    def for_role(self, role: Role) -> tuple[Provider, ...]:
        minimum = ROLE_MINIMUMS[role]
        return tuple(provider for provider in self.providers if provider.capabilities.meets(minimum))

    @property
    def can_fix(self) -> bool:
        return self.host is not None or bool(self.for_role(Role.PATCHER))


@dataclass
class FixContext:
    """Everything a check node or repair step may read."""

    root: Path
    sandbox: Sandbox
    team: Team
    base_ref: str | None = None
    spec: str | None = None
    progress: Callable[[str], None] = field(default=lambda _line: None)


@dataclass(frozen=True)
class CheckNode:
    name: str
    cost: CostClass
    hard_fail: bool
    run: Callable[[FixContext], CheckResult]


class RunOutcome(str, Enum):
    READY = "ready"
    FIXED = "fixed"
    NEEDS_YOU = "needs_you"


@dataclass(frozen=True)
class RunResult:
    outcome: RunOutcome
    summary: str
    branch: str | None = None
    commits: tuple[str, ...] = ()
    evidence: tuple[Evidence, ...] = ()
    questions: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.outcome is RunOutcome.READY and (self.commits or self.branch):
            raise ValueError("ready means nothing changed")
        if self.outcome is RunOutcome.FIXED and not (self.branch and self.commits):
            raise ValueError("fixed needs a branch and at least one commit")
        if self.outcome is RunOutcome.NEEDS_YOU and not self.questions:
            raise ValueError("needs_you must ask the user something")
