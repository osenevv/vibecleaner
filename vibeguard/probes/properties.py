"""Property tests written from the spec and signatures, never the bodies."""

from __future__ import annotations

import ast
import json
import os
from pathlib import Path

from vibeguard.fix_contract import (
    Evidence,
    EvidenceKind,
    FixContext,
    ProviderError,
    Role,
)
from vibeguard.probes.execute import (
    PROBE_TIMEOUT_S,
    ProbeRunError,
    classify_probe,
    combined_output,
    digest,
    ensure_hypothesis,
    hypothesis_prelude,
    judge_note,
    pass_result,
    prune_vibeguard,
    pytest_argv,
    python_executable,
    remove_path,
    revise_result,
    sandbox_run,
    shrunk_example,
    under_root,
)
from vibeguard.probes.spans import ChangedLines
from vibeguard.probes.targets import Target, select_targets

_TARGET_LIMIT = 20
_SYSTEM = (
    "You write property tests from a spec and function signatures. "
    "Reply with one JSON object only. You do not invent function bodies."
)
_PY_INSTRUCTIONS = """
Return JSON: {"properties": [{"name": string, "statement": string, "test": string}]}
"statement" is one plain-English sentence of the invariant.
"test" is one pytest function. `given` and `st` are already imported.
The import lines above are already present. Do not repeat them.
Do not set a seed, max_examples, or @settings. The runner loads a fixed profile
(derandomized, bounded examples).
Use only the spec, the signatures, the docstrings, and the type hints.
""".strip()
_TS_INSTRUCTIONS = """
Return JSON: {"properties": [{"name": string, "statement": string, "test": string}]}
"statement" is one plain-English sentence of the invariant.
"test" is one vitest test() body. `fc` and `test` are already imported.
The import lines above are already present. Do not repeat them.
Call fc.assert with { seed: 1, numRuns: 25 }.
Use only the spec, the signatures, the docstrings, and the type hints.
""".strip()


def property_check(ctx: FixContext, cwd: Path, changed: ChangedLines):
    cwd = Path(cwd)
    notes: list[Evidence] = []
    evidence: list[Evidence] = []
    wrote: list[Path] = []
    try:
        targets = select_targets(cwd, changed)
        if not targets:
            notes.append(judge_note("no pure functions overlap the changed lines"))
            return pass_result("properties", notes)
        if len(targets) > _TARGET_LIMIT:
            notes.append(judge_note(f"property targets capped at {_TARGET_LIMIT}"))
            targets = targets[:_TARGET_LIMIT]
        ctx.progress(f"properties: {len(targets)} targets")
        grouped: dict[str, list[Target]] = {}
        for target in targets:
            grouped.setdefault(target.language, []).append(target)
        for language, group in grouped.items():
            _run_language(ctx, cwd, language, group, notes, evidence, wrote)
    finally:
        for path in wrote:
            remove_path(path)
        prune_vibeguard(cwd)
    if evidence:
        return revise_result("properties", evidence, notes)
    return pass_result("properties", notes)


def _run_language(
    ctx: FixContext,
    cwd: Path,
    language: str,
    targets: list[Target],
    notes: list[Evidence],
    evidence: list[Evidence],
    wrote: list[Path],
) -> None:
    payload, status = _ask(ctx, _prompt(ctx.spec, targets, language), cwd, wrote)
    if payload is None:
        if status == "absent":
            notes.append(judge_note("properties were not generated"))
        else:
            notes.append(judge_note(status or "properties were not generated"))
        return
    properties = _parse_properties(payload)
    if properties is None:
        notes.append(judge_note("tester returned unreadable JSON"))
        return
    if not properties:
        notes.append(judge_note("tester returned no properties"))
        return
    if language == "python":
        problem = ensure_hypothesis(ctx, cwd)
        if problem:
            notes.append(judge_note(f"hypothesis is unavailable: {problem}"))
            return
    for prop in properties:
        _run_property(ctx, cwd, language, targets, prop, notes, evidence, wrote)


def _run_property(
    ctx: FixContext,
    cwd: Path,
    language: str,
    targets: list[Target],
    prop: _Property,
    notes: list[Evidence],
    evidence: list[Evidence],
    wrote: list[Path],
) -> None:
    subject = _subject(prop.test, targets)
    if language == "python":
        text = _python_file(targets, prop.test)
        try:
            ast.parse(text)
        except SyntaxError as exc:
            notes.append(judge_note(f"discarded {prop.name}: {exc.msg}"))
            return
        path = _probe_path(cwd, f"test_props_{digest(text)}.py")
    else:
        path = _probe_path(cwd, f"test_props_{digest(prop.test)}.test.ts")
        text = _typescript_file(cwd, path, targets, prop.test)
    wrote.append(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    rel = path.relative_to(cwd.resolve()).as_posix()
    python = python_executable(ctx.sandbox)
    if language == "python":
        command = pytest_argv(python, rel)
    else:
        command = ("npx", "vitest", "run", rel)
    ctx.progress(f"properties: {prop.name}")
    try:
        result = sandbox_run(ctx, command, cwd=cwd, timeout_s=PROBE_TIMEOUT_S, network=language != "python")
    except ProbeRunError as exc:
        notes.append(judge_note(f"discarded {prop.name}: {exc}"))
        return
    kind = classify_probe(result, path.name)
    output = combined_output(result)
    if kind == "counterexample":
        example = shrunk_example(output) or "timed out"
        evidence.append(
            Evidence(
                kind=EvidenceKind.COUNTEREXAMPLE,
                summary=prop.statement,
                file=subject.path,
                line=subject.start_line,
                command=tuple(command),
                output=output,
                reproducer=example,
            )
        )
        return
    if kind == "note":
        detail = shrunk_example(output) or output
        notes.append(judge_note(f"discarded {prop.name}: {detail}"))


def _ask(ctx: FixContext, prompt: str, cwd: Path, wrote: list[Path]) -> tuple[str | None, str]:
    providers = ctx.team.for_role(Role.TESTER)
    provider_error = ""
    if providers:
        try:
            return providers[0].complete(_SYSTEM, prompt, json_mode=True), "ok"
        except ProviderError as exc:
            provider_error = str(exc)
    host = ctx.team.host
    if host is None:
        return None, "absent" if not provider_error else provider_error
    scratch = under_root(cwd, cwd / ".vibeguard" / "probes" / "ask")
    wrote.append(scratch)
    scratch.mkdir(parents=True, exist_ok=True)
    instructions = (
        "Write the JSON document to properties.json in the worktree. "
        "Do not modify any other file.\n\n" + prompt
    )
    try:
        result = host.run_task(scratch, instructions, timeout_s=120)
    except OSError as exc:
        return None, str(exc)
    payload = scratch / "properties.json"
    if payload.is_file():
        try:
            return payload.read_text(encoding="utf-8"), "ok"
        except OSError as exc:
            return None, str(exc)
    if result.stdout.strip():
        return result.stdout, "ok"
    return None, provider_error or "absent"


def _prompt(spec: str | None, targets: list[Target], language: str) -> str:
    lines = ["SPEC:", spec if spec else "(none)", "", "FUNCTIONS:"]
    for target in targets:
        lines.append(f"file: {target.path}")
        lines.append(f"language: {target.language}")
        lines.append(f"qualname: {target.qualname}")
        lines.append(target.signature)
        if target.docstring:
            lines.append('"""')
            lines.append(target.docstring)
            lines.append('"""')
        if target.language == "python" and target.module:
            imported = target.qualname.split(".")[0]
            lines.append(f"import: from {target.module} import {imported}")
        lines.append("")
    lines.append(_PY_INSTRUCTIONS if language == "python" else _TS_INSTRUCTIONS)
    return "\n".join(lines)


def _python_file(targets: list[Target], test: str) -> str:
    body = "\n".join(line for line in test.splitlines() if not line.lstrip().startswith("@settings"))
    return hypothesis_prelude() + "\n" + _import_block(targets) + "\n\n" + body.strip() + "\n"


def _typescript_file(cwd: Path, path: Path, targets: list[Target], test: str) -> str:
    lines = ['import { test } from "vitest";', 'import fc from "fast-check";', ""]
    grouped: dict[str, list[str]] = {}
    for target in targets:
        names = grouped.setdefault(target.path, [])
        if target.name not in names:
            names.append(target.name)
    for rel, names in grouped.items():
        source = (cwd / rel).with_suffix("")
        relative = Path(os.path.relpath(source, path.parent)).as_posix()
        if not relative.startswith("."):
            relative = "./" + relative
        lines.append(f'import {{ {", ".join(names)} }} from "{relative}";')
    lines.extend(["", test.strip(), ""])
    return "\n".join(lines)


def _import_block(targets: list[Target]) -> str:
    grouped: dict[str, list[str]] = {}
    for target in targets:
        if target.language != "python" or not target.module:
            continue
        name = target.qualname.split(".")[0]
        names = grouped.setdefault(target.module, [])
        if name not in names:
            names.append(name)
    return "\n".join(f"from {module} import {', '.join(names)}" for module, names in grouped.items())


def _subject(test: str, targets: list[Target]) -> Target:
    best = targets[0]
    index = len(test) + 1
    for target in targets:
        found = test.find(target.name)
        if 0 <= found < index:
            best = target
            index = found
    return best


def _probe_path(cwd: Path, name: str) -> Path:
    return under_root(cwd, cwd / ".vibeguard" / "probes" / name)


class _Property:
    def __init__(self, name: str, statement: str, test: str) -> None:
        self.name = name
        self.statement = statement
        self.test = test


def _parse_properties(payload: str) -> list[_Property] | None:
    try:
        data = json.loads(_extract_json(payload))
    except json.JSONDecodeError:
        return None
    items = data.get("properties") if isinstance(data, dict) else data
    if not isinstance(items, list):
        return None
    properties: list[_Property] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        statement = item.get("statement")
        test = item.get("test")
        if not all(isinstance(value, str) and value.strip() for value in (name, statement, test)):
            continue
        properties.append(_Property(name.strip(), statement.strip(), test))
    return properties


def _extract_json(payload: str) -> str:
    text = payload.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        lines = lines[1:]
        if lines and lines[-1].startswith("```"):
            lines = lines[:-1]
        text = "\n".join(lines).strip()
    start = text.find("{")
    end = text.rfind("}")
    if start >= 0 and end > start:
        return text[start : end + 1]
    start = text.find("[")
    end = text.rfind("]")
    if start >= 0 and end > start:
        return text[start : end + 1]
    return text
