"""Turn a repository into ready, fixed, or a question for the user.

Patch search is still the repair package. This loop refuses to call a run
fixed until that search has committed a proven repair.
"""

from __future__ import annotations

from collections.abc import Callable
import hashlib
from pathlib import Path
import tempfile
import uuid

from vibecleaner.agents.team import describe_team, select_team
from vibecleaner.fix_contract import (
    CheckResult,
    FixContext,
    ProviderError,
    RunOutcome,
    RunResult,
    SandboxUnavailable,
    Team,
    Verdict,
)
from vibecleaner.jury.panel import run_panel
from vibecleaner.jury.scan_nodes import ScanLedger, run_static
from vibecleaner.repair.workspace import (
    add_worktree,
    capture_diff,
    changed_lines,
    commit_tree,
    dirty_paths,
    head_sha,
    is_work_tree,
    remove_worktree,
)
from vibecleaner.run.gitcmd import GitError, git
from vibecleaner.run.options import RunOptions
from vibecleaner.runtime.check import runtime_check
from vibecleaner.verify.gates import run_gates
from vibecleaner.verify.sandbox import HostSandbox, make_sandbox
from vibecleaner.verify.tamper import check_tamper, snapshot
from vibecleaner.workflow.interface import apply_interface

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
    summary = "Project code was not executed."
    if static.verdict is Verdict.REVISE:
        questions.append(_team_line(team))
    else:
        blocked, applied = apply_interface(ctx)
        if blocked is not None:
            questions.extend(blocked.questions)
            summary = blocked.summary
        elif applied:
            summary = "The interface instruction ran. Project code was not executed."
    result = RunResult(
        RunOutcome.NEEDS_YOU,
        summary,
        evidence=static.evidence,
        questions=tuple(questions),
    )
    _write_report(root, result)
    return result


def _check(ctx: FixContext, team: Team) -> RunResult:
    ctx.progress("Checking the code")
    static = run_static(ctx, ScanLedger())
    if static.verdict is Verdict.REVISE:
        return _attempt_fix(ctx, team, static, "The static check found a problem.")
    ctx.progress("Running your tests")
    gates = run_gates(ctx, ctx.root)
    if gates.verdict is Verdict.REVISE:
        return _attempt_fix(ctx, team, gates, "A project check failed.")
    runtime = runtime_check(ctx, ctx.root)
    if runtime.verdict is Verdict.REVISE:
        return _attempt_fix(ctx, team, runtime, "The runtime check failed.")
    blocked, applied = apply_interface(ctx)
    if blocked is not None:
        return blocked
    if gates.verdict is Verdict.ESCALATE:
        return RunResult(
            RunOutcome.NEEDS_YOU,
            "No test, type, or lint command was found.",
            questions=("Which command should run the checks? Add it under test in .vibecleaner/config.json.",),
        )
    summary = "Every check that ran passed, and nothing changed."
    if applied:
        summary = "Every check that ran passed. The interface instruction ran."
    return RunResult(RunOutcome.READY, summary)


def _attempt_fix(ctx: FixContext, team: Team, failure: CheckResult, summary: str) -> RunResult:
    if team.host is None or not is_work_tree(ctx.root):
        return _blocked(failure, team, summary)
    base_sha = head_sha(ctx.root)
    before = snapshot(ctx.root)
    seen_states: set[tuple[tuple[str, ...], str]] = set()
    current_failure = failure
    for attempt in range(1, 3):
        run_id = uuid.uuid4().hex[:8]
        branch = f"vibecleaner/fix-{run_id}"
        worktree = Path(tempfile.mkdtemp(prefix=f"vibecleaner-fix-{run_id}-")) / "tree"
        try:
            add_worktree(ctx.root, worktree, base_sha, branch=branch)
        except GitError:
            return _blocked(current_failure, team, summary)
        try:
            ctx.progress(f"Fixing on {branch} (attempt {attempt})")
            prompt = _fix_prompt(current_failure, ctx.spec)
            try:
                outcome = team.host.run_task(worktree, prompt, timeout_s=180)
            except (ProviderError, OSError):
                _cleanup_branch(ctx.root, worktree, branch)
                return _blocked(current_failure, team, summary)
            if not outcome.ok:
                _cleanup_branch(ctx.root, worktree, branch)
                return _blocked(current_failure, team, summary)
            tamper = check_tamper(before, worktree)
            if tamper.verdict is Verdict.REVISE:
                _cleanup_branch(ctx.root, worktree, branch)
                return RunResult(
                    RunOutcome.NEEDS_YOU,
                    "Candidate fix tampered with tests, config, or public signatures and was rejected.",
                    evidence=tamper.evidence,
                    questions=("Fix the failure without weakening tests or config, then run vibecleaner start again.",),
                )
            diff_text = capture_diff(worktree)
            diff_hash = hashlib.sha256(diff_text.encode("utf-8", errors="replace")).hexdigest()
            wt_ctx = FixContext(
                root=worktree,
                sandbox=HostSandbox(worktree) if ctx.sandbox.name == "host" else ctx.sandbox,
                team=team,
                base_ref=ctx.base_ref,
                spec=ctx.spec,
                progress=ctx.progress,
            )
            re_static = run_static(wt_ctx, ScanLedger())
            re_gates = run_gates(wt_ctx, worktree)
            if re_static.verdict is Verdict.REVISE or re_gates.verdict is Verdict.REVISE:
                still = re_static if re_static.verdict is Verdict.REVISE else re_gates
                sig = (tuple(item.summary for item in still.evidence), diff_hash)
                _cleanup_branch(ctx.root, worktree, branch)
                if sig in seen_states:
                    return RunResult(
                        RunOutcome.NEEDS_YOU,
                        "Stopped because the same failing findings and diff repeated.",
                        evidence=still.evidence,
                        questions=("Fix the repeated failure below, then run vibecleaner start again.",),
                    )
                seen_states.add(sig)
                current_failure = still
                continue
            verdict = run_panel(wt_ctx, changed_lines(worktree, base_sha))
            if verdict.verdict is Verdict.REVISE:
                _cleanup_branch(ctx.root, worktree, branch)
                current_failure = verdict
                continue
            try:
                sha = commit_tree(worktree, f"vibecleaner: fix {failure.node} findings")
            except GitError:
                _cleanup_branch(ctx.root, worktree, branch)
                return _blocked(current_failure, team, summary)
            remove_worktree(ctx.root, worktree)
            return RunResult(
                RunOutcome.FIXED,
                f"Fixed on {branch} ({sha[:8]}).",
                branch=branch,
                commits=(sha,),
                evidence=failure.evidence,
            )
        except Exception:
            _cleanup_branch(ctx.root, worktree, branch)
            raise
    return _blocked(current_failure, team, summary)


def _cleanup_branch(root: Path, worktree: Path, branch: str) -> None:
    remove_worktree(root, worktree)
    git(root, "branch", "-D", branch, check=False)


def _fix_prompt(failure: CheckResult, spec: str | None) -> str:
    evidence = "; ".join(item.summary.replace("\n", " ") for item in failure.evidence)
    parts = [
        "Fix the failing check below. Do not weaken or delete tests, config, or public signatures.",
        "Do not run vibecleaner.",
        f"Evidence: {evidence}",
    ]
    if spec:
        parts.append("Spec: " + " ".join(spec.split()))
    return " ".join(parts)


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
