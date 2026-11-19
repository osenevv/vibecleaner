"""Run the base ref and the working tree on the same generated inputs."""

from __future__ import annotations

import ast
import subprocess
from pathlib import Path

from vibecleaner.fix_contract import Evidence, EvidenceKind, FixContext
from vibecleaner.probes.execute import (
    PROBE_TIMEOUT_S,
    ProbeRunError,
    classify_probe,
    combined_output,
    digest,
    ensure_hypothesis,
    hypothesis_prelude,
    judge_note,
    pass_result,
    prune_vibecleaner,
    pytest_argv,
    python_executable,
    remove_path,
    revise_result,
    sandbox_run,
    shrunk_example,
    under_root,
)
from vibecleaner.probes.spans import ChangedLines, read_text
from vibecleaner.probes.targets import Target, extract_targets, select_targets


def differential_check(ctx: FixContext, cwd: Path, changed: ChangedLines):
    cwd = Path(cwd)
    notes: list[Evidence] = []
    if not ctx.base_ref:
        notes.append(judge_note("differential skipped: no base_ref"))
        return pass_result("differential", notes)
    wrote: list[Path] = []
    try:
        targets = select_targets(cwd, changed)
        if not targets:
            notes.append(judge_note("differential skipped: no changed functions"))
            return pass_result("differential", notes)
        if any(target.language != "python" for target in targets):
            notes.append(judge_note("differential is Python-only; TypeScript changes were not compared"))
        comparable = _comparable(ctx, cwd, targets, notes)
        if not comparable:
            return pass_result("differential", notes)
        problem = ensure_hypothesis(ctx, cwd)
        if problem:
            notes.append(judge_note(f"hypothesis is unavailable: {problem}"))
            return pass_result("differential", notes)
        ctx.progress(f"differential: {len(comparable)} functions")
        evidence = _run(ctx, cwd, ctx.base_ref, comparable, wrote)
    finally:
        for path in wrote:
            remove_path(path)
        prune_vibecleaner(cwd)
    if evidence:
        return revise_result("differential", evidence, notes)
    return pass_result("differential", notes)


def _comparable(ctx: FixContext, cwd: Path, targets: list[Target], notes: list[Evidence]) -> list[tuple[Target, str]]:
    base_ref = ctx.base_ref or ""
    cached: dict[str, tuple[str | None, str | None]] = {}
    chosen: list[tuple[Target, str]] = []
    for target in targets:
        if target.language != "python":
            continue
        if target.method:
            notes.append(judge_note(f"differential skipped method {target.qualname}"))
            continue
        if target.is_async:
            notes.append(judge_note(f"differential skipped async {target.qualname}"))
            continue
        if target.io:
            notes.append(judge_note(f"differential skipped io function {target.qualname}"))
            continue
        if target.variadic or not target.parameters or any(not annotation for _kind, _name, annotation in target.parameters):
            notes.append(judge_note(f"differential skipped: {target.qualname} has no type hints"))
            continue
        if target.path not in cached:
            cached[target.path] = _git_show(cwd, base_ref, target.path)
        base_text, error = cached[target.path]
        if base_text is None:
            notes.append(judge_note(f"differential skipped: {target.path} is not in {base_ref} ({error})"))
            continue
        base_fn = _same_function(base_text, target)
        if base_fn is None:
            notes.append(judge_note(f"differential skipped: {target.qualname} is not in {base_ref}"))
            continue
        if base_fn.signature_key() != target.signature_key():
            notes.append(judge_note(f"differential skipped: signature of {target.qualname} changed"))
            continue
        chosen.append((target, base_text))
    return chosen


def _run(
    ctx: FixContext,
    cwd: Path,
    base_ref: str,
    comparable: list[tuple[Target, str]],
    wrote: list[Path],
) -> list[Evidence]:
    by_path: dict[str, str] = {}
    for target, base_text in comparable:
        by_path.setdefault(target.path, base_text)
    harness_name = f"test_diff_{digest(base_ref + ''.join(by_path))}.py"
    harness = under_root(cwd, cwd / ".vibecleaner" / "probes" / harness_name)
    wrote.append(harness)
    base_files: dict[str, Path] = {}
    for rel, text in by_path.items():
        name = f"_base_{digest(rel + text)}.py"
        path = under_root(cwd, cwd / ".vibecleaner" / "probes" / name)
        wrote.append(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        base_files[rel] = path
    functions = [target for target, _text in comparable]
    harness.parent.mkdir(parents=True, exist_ok=True)
    harness.write_text(_harness(cwd, functions, base_files), encoding="utf-8")
    rel = harness.relative_to(cwd.resolve()).as_posix()
    command = pytest_argv(python_executable(ctx.sandbox), rel)
    try:
        result = sandbox_run(ctx, command, cwd=cwd, timeout_s=PROBE_TIMEOUT_S)
    except ProbeRunError as exc:
        return []
    kind = classify_probe(result, harness.name)
    if kind != "counterexample":
        return []
    output = combined_output(result)
    example = shrunk_example(output)
    reproducer = _reproducer(output, example)
    evidence: list[Evidence] = []
    failed = _failed_names(output)
    subjects = [target for target in functions if not failed or f"test_diff_{_safe(target.qualname)}_{target.start_line}" in failed]
    if not subjects:
        subjects = functions
    for target in subjects:
        evidence.append(
            Evidence(
                kind=EvidenceKind.DIVERGENCE,
                summary=f"{target.qualname} diverges from {base_ref}",
                file=target.path,
                line=target.start_line,
                command=command,
                output=output,
                reproducer=reproducer or example or output[-1500:],
            )
        )
    return evidence


def _harness(cwd: Path, targets: list[Target], base_files: dict[str, Path]) -> str:
    lines = [
        "import importlib.util",
        hypothesis_prelude(),
        "",
        "def _load(name, path):",
        "    spec = importlib.util.spec_from_file_location(name, path)",
        "    if spec is None or spec.loader is None:",
        "        raise ImportError(name)",
        "    module = importlib.util.module_from_spec(spec)",
        "    spec.loader.exec_module(module)",
        "    return module",
        "",
    ]
    loaded: set[str] = set()
    for target in targets:
        if target.path in loaded:
            continue
        loaded.add(target.path)
        base_alias = "base_" + digest(target.path)
        new_alias = "new_" + digest(target.path)
        lines.append(f"{base_alias} = _load({base_alias!r}, {str(base_files[target.path])!r})")
        lines.append(f"{new_alias} = _load({new_alias!r}, {str((cwd / target.path).resolve())!r})")
    lines.append("")
    for target in targets:
        base_alias = "base_" + digest(target.path)
        new_alias = "new_" + digest(target.path)
        names = [name for _kind, name, _ann in target.parameters]
        strategies = ", ".join(f"st.from_type({annotation})" for _kind, _name, annotation in target.parameters)
        call_base = _call(f"{base_alias}.{target.name}", target)
        call_new = _call(f"{new_alias}.{target.name}", target)
        fn_name = f"test_diff_{_safe(target.qualname)}_{target.start_line}"
        lines.extend(
            [
                f"@given({strategies})",
                f"def {fn_name}({', '.join(names)}):",
                "    def _outcome(fn):",
                "        try:",
                "            return ('return', fn())",
                "        except Exception as exc:",
                "            return ('raise', type(exc).__name__)",
                f"    left = _outcome(lambda: {call_base})",
                f"    right = _outcome(lambda: {call_new})",
                "    assert left == right, 'input=%r base=%r new=%r' % ((" + ", ".join(names) + ",), left, right)",
                "",
            ]
        )
    return "\n".join(lines)


def _call(fn: str, target: Target) -> str:
    parts: list[str] = []
    for kind, name, _annotation in target.parameters:
        if kind == "kwonly":
            parts.append(f"{name}={name}")
        else:
            parts.append(name)
    return f"{fn}({', '.join(parts)})"


def _same_function(source: str, target: Target) -> Target | None:
    for item in extract_targets(target.path, source):
        if item.qualname == target.qualname:
            return item
    return None


def _git_show(cwd: Path, ref: str, rel: str) -> tuple[str | None, str | None]:
    if ref.startswith("-"):
        return None, "base_ref must not start with -"
    try:
        proc = subprocess.run(
            ["git", "show", f"{ref}:{rel}"],
            cwd=cwd,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except OSError as exc:
        return None, str(exc)
    except subprocess.TimeoutExpired:
        return None, "git show timed out"
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout).strip()
        return None, detail or f"git show failed for {rel}"
    if "\0" in proc.stdout:
        return None, "base file is not text"
    return proc.stdout, None


def _reproducer(output: str, example: str) -> str:
    marker = output.find("input=")
    extra = ""
    if marker >= 0:
        line = output[marker:].splitlines()[0]
        extra = line[1:].lstrip() if line.startswith("E") else line.strip()
    parts = [part for part in (extra, example) if part]
    return "\n".join(parts)


def _failed_names(output: str) -> set[str]:
    names: set[str] = set()
    for line in output.splitlines():
        if "FAILED" in line and "::" in line:
            names.add(line.split("::", 1)[1].split()[0].split("-", 1)[0])
    return names


def _safe(name: str) -> str:
    cleaned = "".join(char if char.isalnum() else "_" for char in name)
    return cleaned or "fn"


# ast is used by the harness string only; keep the import for signature checks that parse.
_ = ast
