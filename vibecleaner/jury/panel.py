"""Specialist judges. A finding blocks only after its probe fails on the current code."""

from __future__ import annotations

import logging
import sys
from collections.abc import Mapping
from pathlib import Path

from vibecleaner.fix_contract import (
    CheckResult,
    Evidence,
    EvidenceKind,
    FixContext,
    Verdict,
)
from vibecleaner.jury.asking import iter_judges
from vibecleaner.jury.parsing import parse_model_json
from vibecleaner.jury.slices import slice_changed

log = logging.getLogger("vibecleaner.jury")

SPECIALISTS: tuple[tuple[str, str, str], ...] = (
    ("races", "concurrency and races", "Looking for races"),
    ("edge_cases", "edge cases", "Looking for edge cases"),
    ("error_handling", "error handling", "Checking error handling"),
    ("abstraction", "leaky abstractions and overcomplication", "Checking for needless complexity"),
)

_SYSTEM = (
    "You are a specialist reviewer for {title}. "
    "Look only at the changed functions and their callers. "
    'Return JSON {{"findings": [{{"file", "line", "function", "problem", "why", "change", "probe"}}]}}. '
    "probe is an optional pytest or vitest test that fails on the current code. "
    "Return an empty findings list when nothing is wrong."
)


def run_specialist(
    ctx: FixContext,
    name: str,
    title: str,
    changed: Mapping[str, frozenset[int]],
) -> CheckResult:
    judges = iter_judges(ctx.team)
    if not judges:
        return CheckResult(name, Verdict.PASS)
    system = _SYSTEM.format(title=title)
    prompt = slice_changed(ctx.root, changed) or "No changed functions."
    evidence: list[Evidence] = []
    notes: list[Evidence] = []
    for index, judge in enumerate(judges):
        try:
            raw = judge.complete(system, prompt, json_mode=True)
        except Exception as exc:
            from vibecleaner.fix_contract import ProviderError

            if not isinstance(exc, ProviderError):
                raise
            log.warning("judge %s failed: %s", judge.name, exc)
            continue
        payload = parse_model_json(raw)
        findings = _findings(payload)
        for offset, finding in enumerate(findings):
            _classify(ctx, name, finding, index * 100 + offset, evidence, notes)
    if evidence:
        return CheckResult(name, Verdict.REVISE, evidence=tuple(evidence), notes=tuple(notes))
    return CheckResult(name, Verdict.PASS, notes=tuple(notes))


def _classify(
    ctx: FixContext,
    node: str,
    finding: dict[str, object],
    index: int,
    evidence: list[Evidence],
    notes: list[Evidence],
) -> None:
    problem = str(finding.get("problem") or "a specialist raised a concern")
    probe = finding.get("probe")
    file = finding.get("file")
    line = finding.get("line")
    file_text = file if isinstance(file, str) else None
    line_no = line if isinstance(line, int) else None
    if not isinstance(probe, str) or not probe.strip():
        notes.append(Evidence(EvidenceKind.JUDGE_NOTE, problem, file=file_text, line=line_no))
        return
    command, result = _run_probe(ctx, probe, index)
    if result.ok or not _real_failure(result.stdout + result.stderr):
        notes.append(Evidence(EvidenceKind.JUDGE_NOTE, problem, file=file_text, line=line_no))
        return
    output = f"{result.stdout}\n{result.stderr}".strip()
    evidence.append(
        Evidence(
            EvidenceKind.TEST_FAILURE,
            problem,
            file=file_text,
            line=line_no,
            command=command,
            output=output or problem,
        )
    )


def _run_probe(ctx: FixContext, probe: str, index: int):
    scratch = ctx.root / ".vibecleaner" / "jury"
    scratch.mkdir(parents=True, exist_ok=True)
    suffix = ".ts" if "vitest" in probe or "from 'vitest'" in probe else ".py"
    path = scratch / f"probe_{index}{suffix}"
    path.write_text(_body(probe, suffix), encoding="utf-8")
    relative = path.relative_to(ctx.root).as_posix()
    if suffix == ".py":
        command = (
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "--tb=line",
            "-p",
            "no:cacheprovider",
            "--noconftest",
            "--rootdir",
            str(ctx.root),
            relative,
        )
    else:
        command = ("npx", "vitest", "run", relative)
    result = ctx.sandbox.run(command, cwd=ctx.root, timeout_s=30)
    if result.ok:
        path.unlink(missing_ok=True)
    return command, result


def _body(probe: str, suffix: str) -> str:
    if "def test_" in probe or "it(" in probe or "test(" in probe:
        return probe if probe.endswith("\n") else probe + "\n"
    if suffix == ".py":
        return f"def test_probe():\n    {probe.strip()}\n"
    return probe


def _findings(payload: object) -> list[dict[str, object]]:
    if isinstance(payload, dict):
        rows = payload.get("findings", [])
    elif isinstance(payload, list):
        rows = payload
    else:
        return []
    if not isinstance(rows, list):
        return []
    return [row for row in rows if isinstance(row, dict)]


def _real_failure(output: str) -> bool:
    if "No module named pytest" in output or "No module named vitest" in output:
        return False
    if "not found" in output.lower() and "vitest" in output.lower():
        return False
    return True
