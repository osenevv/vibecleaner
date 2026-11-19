"""Headless host CLIs. One argv builder, shared with ``--autofix``."""

from __future__ import annotations

import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from vibecleaner.fix_contract import ExecResult, ProviderError

_PRESETS = frozenset({"claude", "codex", "gemini", "agy"})


def preset_argv(name: str, instructions: str) -> list[str]:
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
    try:
        proc = subprocess.run(
            argv,
            cwd=cwd,
            capture_output=capture,
            text=True,
            errors="replace",
            stdin=subprocess.DEVNULL if capture else None,
            timeout=timeout_s,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return ExecResult(
            command=tuple(argv),
            returncode=124,
            stdout=_captured(exc.stdout),
            stderr=_captured(exc.stderr),
            duration_s=time.monotonic() - started,
            timed_out=True,
        )
    except FileNotFoundError as exc:
        if shutil.which(argv[0]) is None and not Path(argv[0]).is_file():
            raise ProviderError(f"agent command not found: {argv[0]}") from exc
        raise ProviderError(f"failed to run {argv[0]} in {cwd}: {exc}") from exc
    except OSError as exc:
        raise ProviderError(f"failed to run {argv[0]} in {cwd}: {exc}") from exc
    return ExecResult(
        command=tuple(argv),
        returncode=proc.returncode,
        stdout=_captured(proc.stdout),
        stderr=_captured(proc.stderr),
        duration_s=time.monotonic() - started,
        timed_out=False,
    )


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
