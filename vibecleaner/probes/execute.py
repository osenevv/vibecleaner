"""Sandbox runs, Hypothesis settings, and probe verdict helpers."""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

from vibecleaner.fix_contract import (
    CheckResult,
    Evidence,
    EvidenceKind,
    ExecResult,
    FixContext,
    Sandbox,
    SandboxUnavailable,
    Verdict,
    clip,
)

MAX_EXAMPLES = 25
PROBE_TIMEOUT_S = 30.0

_SHRINK_MARKERS = ("Falsifying example:", "Failing test case:", "Counterexample:")
_TOOL_ERRORS = (
    "hypothesis.errors.InvalidArgument",
    "hypothesis.errors.Unsatisfiable",
    "hypothesis.errors.FailedHealthCheck",
    "hypothesis.errors.Flaky",
    "ERROR collecting",
)
_FRAME = re.compile(
    r"(?:(?P<path>[\w./\\-]+\.py):\d+|File \"(?P<file>[^\"]+\.py)\", line \d+)"
)


class ProbeRunError(RuntimeError):
    """The sandbox could not run a probe command."""


def on_host(sandbox: Sandbox) -> bool:
    return "docker" not in sandbox.name.lower()


def python_executable(sandbox: Sandbox) -> str:
    if on_host(sandbox):
        return sys.executable
    return "python"


def run_env(sandbox: Sandbox, extra: dict[str, str] | None = None) -> dict[str, str]:
    if on_host(sandbox):
        env = dict(os.environ)
        bindir = str(Path(sys.executable).resolve().parent)
        current = env.get("PATH", "")
        if bindir not in current.split(os.pathsep):
            env["PATH"] = bindir + os.pathsep + current
    else:
        env = {}
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONHASHSEED"] = "0"
    if extra:
        env.update(extra)
    return env


def sandbox_run(
    ctx: FixContext,
    command: tuple[str, ...] | list[str],
    *,
    cwd: Path,
    timeout_s: float,
    network: bool = False,
    env: dict[str, str] | None = None,
) -> ExecResult:
    try:
        return ctx.sandbox.run(
            tuple(command),
            cwd=cwd,
            timeout_s=timeout_s,
            network=network,
            env=env if env is not None else run_env(ctx.sandbox),
        )
    except SandboxUnavailable as exc:
        raise ProbeRunError(str(exc)) from exc
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ProbeRunError(str(exc)) from exc


def ensure_hypothesis(ctx: FixContext, cwd: Path) -> str | None:
    python = python_executable(ctx.sandbox)
    env = run_env(ctx.sandbox)
    try:
        probe = sandbox_run(ctx, (python, "-c", "import hypothesis"), cwd=cwd, timeout_s=30, env=env)
    except ProbeRunError as exc:
        return str(exc)
    if probe.ok:
        return None
    try:
        installed = sandbox_run(
            ctx,
            (python, "-m", "pip", "install", "hypothesis"),
            cwd=cwd,
            timeout_s=120,
            network=True,
            env=env,
        )
    except ProbeRunError as exc:
        return str(exc)
    if installed.ok:
        return None
    return clip(installed.stdout + "\n" + installed.stderr)


def hypothesis_prelude() -> str:
    return (
        "from hypothesis import HealthCheck, given, settings, strategies as st\n"
        "\n"
        "settings.register_profile(\n"
        '    "vibecleaner",\n'
        "    derandomize=True,\n"
        f"    max_examples={MAX_EXAMPLES},\n"
        "    database=None,\n"
        "    deadline=None,\n"
        "    suppress_health_check=[HealthCheck.too_slow, HealthCheck.filter_too_much],\n"
        ")\n"
        'settings.load_profile("vibecleaner")\n'
    )


def pytest_argv(python: str, *paths: str, stop: bool = False) -> tuple[str, ...]:
    argv = [python, "-m", "pytest", "-q"]
    if stop:
        argv.append("-x")
    else:
        argv.extend(("-p", "no:cacheprovider"))
    argv.extend(paths)
    return tuple(argv)


def combined_output(result: ExecResult) -> str:
    parts = [result.stdout, result.stderr]
    if result.timed_out:
        parts.append(f"timed out after {result.duration_s:.1f}s")
    return "\n".join(part for part in parts if part)


def judge_note(summary: str) -> Evidence:
    return Evidence(EvidenceKind.JUDGE_NOTE, _short(summary))


def pass_result(node: str, notes: list[Evidence]) -> CheckResult:
    return CheckResult(node, Verdict.PASS, notes=tuple(notes))


def revise_result(node: str, evidence: list[Evidence], notes: list[Evidence]) -> CheckResult:
    return CheckResult(node, Verdict.REVISE, evidence=tuple(evidence), notes=tuple(notes))


def classify_probe(result: ExecResult, test_name: str) -> str:
    """Return pass, note, or counterexample."""
    if result.timed_out:
        return "counterexample"
    output = combined_output(result)
    if result.returncode == 0:
        return "pass"
    if generated_fault(output, test_name):
        return "note"
    if shrunk_example(output) or "AssertionError" in output:
        return "counterexample"
    return "note"


def generated_fault(output: str, test_name: str) -> bool:
    if any(token in output for token in _TOOL_ERRORS):
        return True
    lowered = output.lower()
    if "cannot find module" in lowered or ("npx" in lowered and "not found" in lowered):
        return True
    if "vitest: not found" in lowered or "pytest: not found" in lowered:
        return True
    if any(token in output for token in ("SyntaxError", "IndentationError", "ModuleNotFoundError", "ImportError", "NameError")):
        return not _enters_project(output, test_name)
    return False


def shrunk_example(output: str) -> str:
    start = -1
    for marker in _SHRINK_MARKERS:
        index = output.rfind(marker)
        if index > start:
            start = index
    if start < 0:
        return ""
    snippet = output[start:]
    for stop in ("\n====", "\n-----", "\n____"):
        cut = snippet.find(stop)
        if cut > 0:
            snippet = snippet[:cut]
            break
    lines = [re.sub(r"^E\s+", "", line) for line in snippet.splitlines()]
    return "\n".join(lines).strip()


def digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]


def under_root(root: Path, path: Path) -> Path:
    resolved_root = root.resolve()
    resolved = path.resolve()
    if resolved != resolved_root and resolved_root not in resolved.parents:
        raise ValueError(f"path escapes the project: {path}")
    return resolved


def remove_path(path: Path) -> None:
    if path.is_dir():
        shutil.rmtree(path)
    elif path.exists():
        path.unlink()


def prune_vibecleaner(cwd: Path) -> None:
    probes = cwd / ".vibecleaner" / "probes"
    if probes.is_dir():
        cache = probes / "__pycache__"
        if cache.is_dir():
            shutil.rmtree(cache)
        if not any(probes.iterdir()):
            probes.rmdir()
    mutants = cwd / ".vibecleaner" / "mutants"
    if mutants.is_dir() and not any(mutants.iterdir()):
        mutants.rmdir()
    root = cwd / ".vibecleaner"
    if root.is_dir() and not any(root.iterdir()):
        root.rmdir()


def _enters_project(output: str, test_name: str) -> bool:
    for match in _FRAME.finditer(output):
        path = (match.group("path") or match.group("file") or "").replace("\\", "/")
        base = path.rsplit("/", 1)[-1]
        if base == test_name or base.startswith("test_"):
            continue
        if "site-packages" in path or "/hypothesis/" in path or base.startswith("_pytest"):
            continue
        return True
    return False


def _short(text: str, limit: int = 300) -> str:
    collapsed = " ".join(text.split())
    if len(collapsed) <= limit:
        return collapsed
    return collapsed[: limit - 3] + "..."
