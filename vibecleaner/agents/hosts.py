"""Headless host CLIs. One argv builder, shared with ``--autofix``."""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from vibecleaner.fix_contract import ExecResult, ProviderError
from typing import Literal

_PRESETS = frozenset({"claude", "codex", "gemini", "agy"})


def preset_argv(name: Literal['claude', 'codex', 'agy', 'gemini'], instructions: str) -> list[str]:
    """Argv for a known agent preset. Flags match the installed CLIs' ``--help``."""
    if name == "claude":
        return ["claude", "-p", instructions, "--permission-mode", "acceptEdits"]
    if name == "codex":
        return ["codex", "exec", instructions]
    if name == "agy":
        return ["agy", "-p", instructions]
    if name == "gemini":
        return ["gemini", "-p", instructions]
    raise ValueError(f"unknown agent preset {name!r}")


def execute_argv(
    argv: list[str],
    *,
    cwd: Path,
    timeout_s: float | None,
    capture: bool,
) -> ExecResult:
    """Run ``argv`` in ``cwd``. ``capture`` keeps stdout for ``ExecResult``; autofix inherits the terminal."""
    if not cwd.is_dir():
        raise ProviderError(f"worktree does not exist: {cwd}")
    allowed_bins = _PRESETS
    if not argv or (argv[0] not in allowed_bins and not Path(argv[0]).expanduser().is_file() and shutil.which(argv[0]) is None):
        raise ProviderError(f"agent command not found: {argv[0] if argv else ''}")
    started = time.monotonic()
    run_argv = list(argv)
    resolved = shutil.which(argv[0])
    if resolved:
        run_argv[0] = resolved
    try:
        proc = subprocess.Popen(
            run_argv,
            cwd=cwd,
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.PIPE if capture else None,
            stdin=subprocess.DEVNULL if capture else None,
            text=True,
            errors="replace",
        )
    except FileNotFoundError as exc:
        if shutil.which(argv[0]) is None and not Path(argv[0]).is_file():
            raise ProviderError(f"agent command not found: {argv[0]}") from exc
        raise ProviderError(f"failed to run {argv[0]} in {cwd}: {exc}") from exc
    except OSError as exc:
        raise ProviderError(f"failed to run {argv[0]} in {cwd}: {exc}") from exc
    try:
        stdout, stderr = proc.communicate(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        _terminate_tree(proc)
        try:
            stdout, stderr = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            stdout, stderr = "", ""
            if proc.stdout is not None:
                proc.stdout.close()
            if proc.stderr is not None:
                proc.stderr.close()
        return ExecResult(
            command=tuple(argv),
            returncode=124,
            stdout=_captured(stdout),
            stderr=_captured(stderr),
            duration_s=time.monotonic() - started,
            timed_out=True,
        )
    return ExecResult(
        command=tuple(argv),
        returncode=proc.returncode,
        stdout=_captured(stdout),
        stderr=_captured(stderr),
        duration_s=time.monotonic() - started,
        timed_out=False,
    )


def _terminate_tree(proc: subprocess.Popen[str]) -> None:
    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    else:
        proc.kill()


def _captured(value: object) -> str:
    return value if isinstance(value, str) else ""


@dataclass(frozen=True)
class CliHost:
    name: str
    family: str
    preset: str

    def run_task(self, worktree: Path, instructions: str, *, timeout_s: float) -> ExecResult:
        if self.preset not in _PRESETS:
            raise ProviderError(f"unknown host preset {self.preset!r}")
        return execute_argv(
            preset_argv(self.preset, instructions),
            cwd=worktree,
            timeout_s=timeout_s,
            capture=True,
        )


_HOSTS: dict[str, tuple[str, str]] = {
    "claude-code": ("anthropic", "claude"),
    "codex": ("openai", "codex"),
    "antigravity": ("gemini", "agy"),
}


def host_from_name(name: str) -> CliHost:
    pair = _HOSTS.get(name)
    if pair is None:
        known = ", ".join(sorted(_HOSTS))
        raise ProviderError(f"unknown VIBECLEANER_HOST {name!r}. Expected {known}.")
    family, preset = pair
    return CliHost(name=name, family=family, preset=preset)
