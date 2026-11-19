"""Host sandbox and tamper checks used until ``vibecleaner.verify`` is present."""

from __future__ import annotations

import ast
import logging
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

from vibecleaner.collector import _is_test_unit_path
from vibecleaner.fix_contract import (
    CheckResult,
    Evidence,
    EvidenceKind,
    ExecResult,
    SandboxUnavailable,
    Verdict,
)

log = logging.getLogger("vibecleaner.run")

_SKIP_DIRS = frozenset(
    {".git", ".vibecleaner", "__pycache__", ".pytest_cache", "node_modules", ".venv", "venv", "dist", "build"}
)
_CODE_SUFFIXES = frozenset({".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"})
_SKIP_MARKERS = (
    "pytest.mark.skip",
    "pytest.mark.xfail",
    "unittest.skip",
    ".only",
    "it.skip",
    "test.skip",
    "describe.skip",
    "xit(",
    "xdescribe(",
)
_ASSERT = re.compile(r"\bassert\b|\bexpect\s*\(")
_BARE_EXCEPT = re.compile(r"except\s*:")


class HostSandbox:
    """Runs commands on this machine, with the project root as the boundary."""

    name = "host"

    def __init__(self, root: Path) -> None:
        self.root = Path(root)

    def run(
        self,
        command: tuple[str, ...] | list[str],
        *,
        cwd: Path,
        timeout_s: float,
        network: bool = False,
        env: dict[str, str] | None = None,
    ) -> ExecResult:
        argv = tuple(command)
        merged = os.environ.copy()
        merged["PYTHONDONTWRITEBYTECODE"] = "1"
        if env:
            merged.update(env)
        started = time.perf_counter()
        try:
            proc = subprocess.run(
                list(argv),
                cwd=cwd,
                capture_output=True,
                text=True,
                timeout=timeout_s,
                env=merged,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            stdout = _text(exc.stdout)
            stderr = _text(exc.stderr)
            return ExecResult(argv, 124, stdout, stderr, time.perf_counter() - started, timed_out=True)
        except OSError as exc:
            log.warning("command failed to start: %s", exc)
            return ExecResult(argv, 127, "", str(exc), time.perf_counter() - started)
        return ExecResult(
            argv,
            proc.returncode,
            proc.stdout,
            proc.stderr,
            time.perf_counter() - started,
        )


def make_sandbox(root: Path, kind: str = "docker") -> HostSandbox:
    if kind == "host":
        return HostSandbox(root)
    if kind != "docker":
        raise SandboxUnavailable(f"unknown sandbox {kind}")
    if not _docker_ready():
        raise SandboxUnavailable("Docker is not available")
    raise SandboxUnavailable("Docker sandbox cannot run project code")


def detect_gates(root: Path) -> tuple[tuple[str, ...], ...]:
    if _has_pytest(root):
        return (
            (
                sys.executable,
                "-m",
                "pytest",
                "-q",
                "--tb=line",
                "-p",
                "no:cacheprovider",
                "--noconftest",
                "--rootdir",
                str(root),
            ),
        )
    return ()


def run_gates(ctx, cwd: Path, gates: tuple[tuple[str, ...], ...] | None = None) -> CheckResult:
    selected = detect_gates(cwd) if gates is None else gates
    if not selected:
        return CheckResult("execution_gate", Verdict.PASS)
    evidence: list[Evidence] = []
    for command in selected:
        result = ctx.sandbox.run(command, cwd=cwd, timeout_s=120)
        if result.ok:
            continue
        output = f"{result.stdout}\n{result.stderr}".strip()
        kind = EvidenceKind.TEST_FAILURE if _is_test_command(command) else EvidenceKind.BUILD_ERROR
        evidence.append(
            Evidence(
                kind,
                _failure_summary(output),
                command=tuple(command),
                output=output,
            )
        )
    if not evidence:
        return CheckResult("execution_gate", Verdict.PASS)
    return CheckResult("execution_gate", Verdict.REVISE, evidence=tuple(evidence))


class TamperSnapshot:
    def __init__(
        self,
        tests: tuple[tuple[str, str, tuple[str, ...]], ...],
        signatures: tuple[tuple[str, str], ...],
    ) -> None:
        self.tests = tests
        self.signatures = signatures


def snapshot(tree: Path) -> TamperSnapshot:
    tests: list[tuple[str, str, tuple[str, ...]]] = []
    signatures: list[tuple[str, str]] = []
    root = Path(tree)
    for path in _code_files(root):
        rel = path.relative_to(root).as_posix()
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            log.warning("skip %s: %s", rel, exc)
            continue
        if _is_test_unit_path(rel):
            tests.append((rel, text, _python_tests(text) if rel.endswith(".py") else ()))
        elif rel.endswith(".py"):
            signatures.extend(_public_signatures(rel, text))
    return TamperSnapshot(tuple(tests), tuple(signatures))


def check_tamper(before: TamperSnapshot, tree: Path, *, allowed_signatures: frozenset[str] = frozenset()) -> CheckResult:
    evidence = _test_changes(before, Path(tree))
    evidence.extend(_signature_changes(before, Path(tree), allowed_signatures))
    if not evidence:
        return CheckResult("tamper_guard", Verdict.PASS)
    return CheckResult("tamper_guard", Verdict.REVISE, evidence=tuple(evidence))


def _docker_ready() -> bool:
    docker = shutil.which("docker")
    if docker is None:
        return False
    try:
        proc = subprocess.run([docker, "info"], capture_output=True, text=True, timeout=5, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        log.warning("docker info failed: %s", exc)
        return False
    return proc.returncode == 0


def _has_pytest(root: Path) -> bool:
    return any(_code_files(root, tests_only=True))


def _code_files(root: Path, *, tests_only: bool = False) -> list[Path]:
    found: list[Path] = []
    if not root.is_dir():
        return found
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [name for name in dirnames if name not in _SKIP_DIRS]
        for name in filenames:
            path = Path(dirpath) / name
            if path.suffix.lower() not in _CODE_SUFFIXES:
                continue
            rel = path.relative_to(root).as_posix()
            if tests_only and not _is_test_unit_path(rel):
                continue
            found.append(path)
    return found


def _python_tests(text: str) -> tuple[str, ...]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return ()
    names = [
        node.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test_")
    ]
    return tuple(sorted(names))


def _public_signatures(path: str, text: str) -> list[tuple[str, str]]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []
    found: list[tuple[str, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if node.name.startswith("_"):
            continue
        args = [arg.arg for arg in node.args.args]
        found.append((f"{path}:{node.name}", f"{node.name}({', '.join(args)})"))
    return found


def _test_changes(before: TamperSnapshot, tree: Path) -> list[Evidence]:
    evidence: list[Evidence] = []
    for rel, text, names in before.tests:
        path = tree / rel
        if not path.is_file():
            evidence.append(_tamper(rel, f"Test file {rel} was deleted"))
            continue
        try:
            current = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            log.warning("could not read %s after the fix: %s", rel, exc)
            continue
        if rel.endswith(".py"):
            current_names = set(_python_tests(current))
            missing = [name for name in names if name not in current_names]
            if missing:
                evidence.append(_tamper(rel, f"Test {missing[0]} was removed from {rel}"))
        if len(_ASSERT.findall(current)) < len(_ASSERT.findall(text)):
            evidence.append(_tamper(rel, f"An assertion in {rel} was weakened"))
        if _count_markers(current) > _count_markers(text):
            evidence.append(_tamper(rel, f"A skip or focused test was added in {rel}"))
        if len(_BARE_EXCEPT.findall(current)) > len(_BARE_EXCEPT.findall(text)):
            evidence.append(_tamper(rel, f"A bare except was added in {rel}"))
    return evidence


def _signature_changes(before: TamperSnapshot, tree: Path, allowed: frozenset[str]) -> list[Evidence]:
    current: dict[str, str] = {}
    for path in _code_files(tree):
        rel = path.relative_to(tree).as_posix()
        if _is_test_unit_path(rel) or not rel.endswith(".py"):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        current.update(dict(_public_signatures(rel, text)))
    evidence: list[Evidence] = []
    for key, signature in before.signatures:
        name = key.split(":")[-1]
        if key in allowed or name in allowed:
            continue
        if key not in current:
            evidence.append(_tamper(key.split(":", 1)[0], f"Public function {name} was removed"))
            continue
        if current[key] != signature:
            evidence.append(_tamper(key.split(":", 1)[0], f"Public signature of {name} changed"))
    return evidence


def _count_markers(text: str) -> int:
    return sum(text.count(marker) for marker in _SKIP_MARKERS)


def _tamper(path: str, summary: str) -> Evidence:
    return Evidence(
        EvidenceKind.TAMPER,
        summary,
        file=path,
        command=("git", "diff", "--", path),
        output=summary,
    )


def _failure_summary(output: str) -> str:
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith("FAILED") or stripped.startswith("E ") or "AssertionError" in stripped:
            return stripped[:240]
    return "a test failed"


def _is_test_command(command: tuple[str, ...]) -> bool:
    joined = " ".join(command)
    return "pytest" in joined or "vitest" in joined or "jest" in joined


def _text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value
