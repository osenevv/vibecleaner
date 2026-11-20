"""Git invocations shared by the fixer. The lock keeps parallel worktrees from colliding."""

from __future__ import annotations

import logging
import subprocess
import threading
from pathlib import Path

log = logging.getLogger("vibeguard.run")
_LOCK = threading.Lock()
_GIT_SUBCOMMANDS = frozenset(
    {
        "add",
        "apply",
        "branch",
        "checkout",
        "clean",
        "commit",
        "config",
        "diff",
        "fetch",
        "init",
        "log",
        "ls-files",
        "merge-base",
        "reset",
        "rev-parse",
        "rm",
        "show",
        "stash",
        "status",
        "switch",
        "symbolic-ref",
        "worktree",
    }
)


class GitError(RuntimeError):
    """Git could not complete a fixer operation."""


def git(
    cwd: Path,
    *args: str,
    input_text: str | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    allowed_subcommands = _GIT_SUBCOMMANDS
    if not args or args[0] not in allowed_subcommands:
        raise GitError(f"unsupported git subcommand: {args[0] if args else ''}")
    try:
        with _LOCK:
            proc = subprocess.run(
                ["git", *args],
                cwd=cwd,
                input=input_text,
                text=True,
                capture_output=True,
                check=False,
            )
    except FileNotFoundError as exc:
        raise GitError("git is not installed") from exc
    if check and proc.returncode != 0:
        detail = proc.stderr.strip() or proc.stdout.strip() or "git failed"
        raise GitError(detail)
    return proc
