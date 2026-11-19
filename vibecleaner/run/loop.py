"""Turn a repository into ready, fixed, or a question for the user.

Patch search is still the repair package. This loop refuses to call a run
fixed until that search has committed a proven repair.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from vibecleaner.agents.team import describe_team, select_team
from vibecleaner.fix_contract import (
    CheckResult,
    FixContext,
    RunOutcome,
    RunResult,
    SandboxUnavailable,
    Team,
    Verdict,
)
from vibecleaner.jury.scan_nodes import ScanLedger, run_static
from vibecleaner.repair.workspace import dirty_paths, is_work_tree
from vibecleaner.run.gitcmd import GitError
from vibecleaner.run.options import RunOptions
from vibecleaner.verify.gates import run_gates
from vibecleaner.verify.sandbox import HostSandbox, make_sandbox

_DOCKER_QUESTION = (
    "Start Docker, or run `vibecleaner start --sandbox host` to run checks on this machine."
)


def start(root: Path, options: RunOptions, progress: Callable[[str], None]) -> RunResult:
    """Check `root` and return one of the three run results."""
    root = Path(root).expanduser().resolve()
    if not root.is_dir():
        raise FileNotFoundError(f"path is not a directory: {root}")
    progress("Reading the repository")
    blocked = _dirty(root)
    if blocked is not None:
        _write_report(root, blocked)
        return blocked
    team = select_team(root, local=options.local)
    try:
        sandbox = make_sandbox(root, options.sandbox)
    except SandboxUnavailable as exc:
        return _without_sandbox(root, options, progress, team, exc)
    spec = _read_spec(options.spec_path)
    ctx = FixContext(
        root=root,
        sandbox=sandbox,
        team=team,
        base_ref=options.base_ref,
        spec=spec,
        progress=progress,
    )
    result = _check(ctx, team)
    _write_report(root, result)
    return result


def exit_code(result: RunResult) -> int:
    """0 when the tree is ready or a fix was committed, 1 when the user must answer."""
    if result.outcome is RunOutcome.NEEDS_YOU:
        return 1
    return 0


def _dirty(root: Path) -> RunResult | None:
    if not is_work_tree(root):
        return None
    try:
        paths = dirty_paths(root)
    except GitError as exc:
        return RunResult(
            RunOutcome.NEEDS_YOU,
            "Git could not read this repository.",
            questions=(str(exc),),
        )
    if not paths:
        return None
    listed = ", ".join(paths[:8])
    return RunResult(
        RunOutcome.NEEDS_YOU,
        f"Uncommitted files are in the way: {listed}.",
        questions=("Commit or stash those files, then run vibecleaner start again.",),
    )


def _without_sandbox(
    root: Path,
    options: RunOptions,
    progress: Callable[[str], None],
    team: Team,
    exc: SandboxUnavailable,
) -> RunResult:
    progress("Checking the files without running the project")
    ctx = FixContext(
        root=root,
        sandbox=HostSandbox(root),
        team=team,
        base_ref=options.base_ref,
        spec=_read_spec(options.spec_path),
        progress=progress,
    )
    static = run_static(ctx, ScanLedger())
    questions = [_DOCKER_QUESTION if options.sandbox == "docker" else str(exc)]
    if static.verdict is Verdict.REVISE:
        questions.append(_team_line(team))
    result = RunResult(
        RunOutcome.NEEDS_YOU,
        "Project code was not executed.",
        evidence=static.evidence,
        questions=tuple(questions),
    )
    _write_report(root, result)
    return result


def _check(ctx: FixContext, team: Team) -> RunResult:
    ctx.progress("Checking the code")
    static = run_static(ctx, ScanLedger())
    if static.verdict is Verdict.REVISE:
        return _blocked(static, team, "The static check found a problem.")
    ctx.progress("Running your tests")
    gates = run_gates(ctx, ctx.root)
    if gates.verdict is Verdict.REVISE:
        return _blocked(gates, team, "A project check failed.")
    if gates.verdict is Verdict.ESCALATE:
        return RunResult(
            RunOutcome.NEEDS_YOU,
            "No test, type, or lint command was found.",
            questions=("Which command should run the checks? Add it under test in .vibecleaner/config.json.",),
        )
    return RunResult(RunOutcome.READY, "Every check that ran passed, and nothing changed.")


def _blocked(result: CheckResult, team: Team, summary: str) -> RunResult:
    question = (
        "Fix the evidence below, then run vibecleaner start again."
        if team.can_fix
        else _team_line(team)
    )
    return RunResult(
        RunOutcome.NEEDS_YOU,
        summary,
        evidence=result.evidence,
        questions=(question,),
    )


def _team_line(team: Team) -> str:
    described = describe_team(team)
    if team.can_fix:
        return described
    return f"{described}. Set VIBECLEANER_HOST or an API key, or start a local model, to unlock fixing."


def _read_spec(path: Path | None) -> str | None:
    if path is None:
        return None
    return Path(path).read_text(encoding="utf-8")


def _write_report(root: Path, result: RunResult) -> None:
    lines = [f"# {result.outcome.value}", "", result.summary, ""]
    if result.questions:
        lines.append("## Questions")
        lines.extend(f"- {question}" for question in result.questions)
        lines.append("")
    if result.evidence:
        lines.append("## Evidence")
        for item in result.evidence:
            command = " ".join(item.command) if item.command else ""
            lines.append(f"- {item.summary}" + (f" (`{command}`)" if command else ""))
        lines.append("")
    path = root / "VIBECLEANER_RUN.md"
    try:
        path.write_text("\n".join(lines), encoding="utf-8")
    except OSError:
        return
