"""Real git repos for tests.

A sandboxed shell may refuse to create `.git/config` and `.git/hooks`.
`git init --separate-git-dir` keeps a normal `.git` file in the work tree
and stores the repository next to it, which those shells allow.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path


def init_git(repo: Path, *, branch: str | None = None) -> Path:
    """Initialize `repo` and set a local commit identity. Returns `repo`."""
    repo.mkdir(parents=True, exist_ok=True)
    if _git_init(repo, branch=branch, git_dir=None) != 0:
        _remove(repo / ".git")
        git_dir = repo.parent / f"{repo.name}.gitdir"
        _remove(git_dir)
        code = _git_init(repo, branch=branch, git_dir=git_dir)
        if code != 0:
            raise RuntimeError(f"git init failed in {repo}")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "Test")
    _git(repo, "config", "commit.gpgsign", "false")
    return repo


def hook_file(repo: Path, name: str = "pre-push") -> Path:
    """Absolute path of a hook, including when `.git` is a gitdir file."""
    proc = _git(repo, "rev-parse", "--git-path", f"hooks/{name}")
    raw = Path(proc.stdout.strip())
    return raw if raw.is_absolute() else (repo / raw).resolve()


def _git_init(repo: Path, *, branch: str | None, git_dir: Path | None) -> int:
    command = ["git", "init", "-q"]
    if branch is not None:
        command.extend(["-b", branch])
    if git_dir is not None:
        command.append(f"--separate-git-dir={git_dir}")
    proc = subprocess.run(command, cwd=repo, capture_output=True, text=True, check=False)
    return proc.returncode


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    )


def _remove(path: Path) -> None:
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path)
    elif path.exists() or path.is_symlink():
        path.unlink()
