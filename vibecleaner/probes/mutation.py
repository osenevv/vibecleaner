"""Mutation score for changed lines. A weak suite is a revise."""

from __future__ import annotations

import difflib
import json
import os
import shutil
from pathlib import Path

from vibecleaner.fix_contract import Evidence, EvidenceKind, ExecResult, FixContext
from vibecleaner.probes.execute import (
    ProbeRunError,
    combined_output,
    judge_note,
    pass_result,
    prune_vibecleaner,
    python_executable,
    remove_path,
    revise_result,
    run_env,
    sandbox_run,
)
from vibecleaner.probes.mutate import Mutant, file_candidates, select_mutants
from vibecleaner.probes.spans import ChangedLines, is_skipped_path, language_of, normalize_changed, read_text

SCORE_THRESHOLD = 0.6
MIN_MUTANTS = 3
MAX_MUTANTS = 20
MUTANT_TIMEOUT_S = 20.0
_SKIP_DIRS = frozenset(
    {
        ".git",
        ".venv",
        "venv",
        "node_modules",
        "__pycache__",
        ".vibecleaner",
        ".pytest_cache",
        ".hypothesis",
        ".mypy_cache",
        ".ruff_cache",
        "dist",
        "build",
        ".tox",
        ".nox",
    }
)
_COPY_SUFFIXES = {
    ".py",
    ".pyi",
    ".toml",
    ".cfg",
    ".ini",
    ".txt",
    ".json",
    ".ts",
    ".tsx",
    ".js",
    ".jsx",
    ".mjs",
    ".cjs",
    ".yml",
    ".yaml",
}
_COPY_NAMES = {"pytest.ini", "setup.cfg", "conftest.py", "package.json", "tsconfig.json", "requirements.txt"}


def mutation_check(ctx: FixContext, cwd: Path, changed: ChangedLines):
    cwd = Path(cwd)
    notes: list[Evidence] = []
    created: list[Path] = []
    try:
        candidates = _collect(cwd, changed)
        if not candidates:
            notes.append(judge_note("no mutants on the changed lines"))
            return pass_result("mutation", notes)
        selected = select_mutants(candidates, MAX_MUTANTS)
        ctx.progress(f"mutation: {len(selected)} mutants")
        return _score(ctx, cwd, selected, notes, created)
    finally:
        for path in created:
            remove_path(path)
        prune_vibecleaner(cwd)


def _score(
    ctx: FixContext,
    cwd: Path,
    mutants: list[Mutant],
    notes: list[Evidence],
    created: list[Path],
) -> object:
    python = python_executable(ctx.sandbox)
    originals = {mutant.path: read_text(cwd, mutant.path) or "" for mutant in mutants}
    template = cwd / ".vibecleaner" / "mutants" / "_base"
    created.append(template)
    _copy_minimal(cwd, template)
    groups: dict[tuple[str, ...], list[Mutant]] = {}
    for mutant in mutants:
        groups.setdefault(_test_argv(cwd, python, mutant.path), []).append(mutant)
    killed = 0
    survived: list[tuple[Mutant, ExecResult, tuple[str, ...]]] = []
    inconclusive = 0
    for command, group in groups.items():
        try:
            baseline = sandbox_run(ctx, command, cwd=template, timeout_s=MUTANT_TIMEOUT_S, env=run_env(ctx.sandbox))
        except ProbeRunError as exc:
            notes.append(judge_note(f"mutation score skipped: {exc}"))
            inconclusive += len(group)
            continue
        if baseline.timed_out:
            notes.append(judge_note("project tests exceeded the per-mutant timeout"))
            inconclusive += len(group)
            continue
        if baseline.returncode == 5:
            notes.append(judge_note("project tests collected nothing; mutation score skipped"))
            inconclusive += len(group)
            continue
        if not baseline.ok:
            notes.append(judge_note("project tests are already failing; mutation score skipped"))
            inconclusive += len(group)
            continue
        for index, mutant in enumerate(group):
            dest = cwd / ".vibecleaner" / "mutants" / str(len(created))
            created.append(dest)
            _replicate(template, dest)
            _write_fresh(dest / mutant.path, mutant.source)
            try:
                result = sandbox_run(ctx, command, cwd=dest, timeout_s=MUTANT_TIMEOUT_S, env=run_env(ctx.sandbox))
            except ProbeRunError as exc:
                notes.append(judge_note(f"mutant {mutant.operator} at {mutant.path}:{mutant.line} did not run: {exc}"))
                inconclusive += 1
                continue
            status = _status(result)
            if status == "killed":
                killed += 1
            elif status == "survived":
                survived.append((mutant, result, command))
            else:
                inconclusive += 1
            del index
    scored = killed + len(survived)
    if inconclusive:
        notes.append(judge_note(f"{inconclusive} mutants were inconclusive"))
    if scored < MIN_MUTANTS:
        notes.append(judge_note(f"mutation score skipped: {scored} mutants; need {MIN_MUTANTS}"))
        return pass_result("mutation", notes)
    score = killed / scored
    notes.append(judge_note(f"mutation score {score:.2f} ({killed}/{scored} killed)"))
    ctx.progress(f"mutation: score {score:.2f}")
    if score >= SCORE_THRESHOLD:
        return pass_result("mutation", notes)
    evidence = [_surviving(item, result, command, originals[item.path]) for item, result, command in survived]
    return revise_result("mutation", evidence, notes)


def _collect(cwd: Path, changed: ChangedLines) -> list[Mutant]:
    found: list[Mutant] = []
    for rel, lines in sorted(normalize_changed(cwd, changed).items()):
        if is_skipped_path(rel) or language_of(rel) is None:
            continue
        text = read_text(cwd, rel)
        if text is None:
            continue
        found.extend(file_candidates(rel, text, lines))
    return found


def _surviving(mutant: Mutant, result: ExecResult, command: tuple[str, ...], original: str) -> Evidence:
    diff = "".join(
        difflib.unified_diff(
            original.splitlines(keepends=True),
            mutant.source.splitlines(keepends=True),
            fromfile=f"a/{mutant.path}",
            tofile=f"b/{mutant.path}",
        )
    )
    return Evidence(
        kind=EvidenceKind.SURVIVING_MUTANT,
        summary=f"surviving mutant {mutant.operator} at {mutant.path}:{mutant.line}",
        file=mutant.path,
        line=mutant.line,
        command=command,
        output=combined_output(result),
        reproducer=diff,
    )


def _status(result: ExecResult) -> str:
    if result.timed_out:
        return "killed"
    if result.returncode == 0:
        return "survived"
    if result.returncode == 1:
        return "killed"
    return "inconclusive"


def _test_argv(cwd: Path, python: str, path: str) -> tuple[str, ...]:
    if path.endswith(".py"):
        return (python, "-m", "pytest", "-q", "-x")
    return _javascript_test_argv(cwd)


def _javascript_test_argv(cwd: Path) -> tuple[str, ...]:
    package = cwd / "package.json"
    if package.is_file():
        try:
            data = json.loads(package.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            data = None
        scripts = data.get("scripts") if isinstance(data, dict) else None
        script = scripts.get("test") if isinstance(scripts, dict) else None
        if isinstance(script, str) and script.strip():
            return ("npm", "test")
    return ("npx", "vitest", "run")


def _copy_minimal(src: Path, dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    for dirpath, dirnames, filenames in os.walk(src):
        current = Path(dirpath)
        rel_dir = current.relative_to(src)
        if any(part in _SKIP_DIRS for part in rel_dir.parts):
            dirnames[:] = []
            continue
        dirnames[:] = [name for name in dirnames if name not in _SKIP_DIRS]
        for name in filenames:
            if Path(name).suffix.lower() not in _COPY_SUFFIXES and name not in _COPY_NAMES:
                continue
            target = dest / rel_dir / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(current / name, target)


def _replicate(src: Path, dest: Path) -> None:
    for dirpath, _dirnames, filenames in os.walk(src):
        current = Path(dirpath)
        rel_dir = current.relative_to(src)
        for name in filenames:
            origin = current / name
            target = dest / rel_dir / name
            target.parent.mkdir(parents=True, exist_ok=True)
            try:
                os.link(origin, target)
            except OSError:
                shutil.copy2(origin, target)


def _write_fresh(path: Path, text: str) -> None:
    if path.exists():
        path.unlink()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
