"""Worktrees, diffs, and the dirty-tree check. Commits happen only inside a fixer worktree."""

from __future__ import annotations

import logging
import re
from pathlib import Path

from vibecleaner.run.gitcmd import GitError, git

log = logging.getLogger("vibecleaner.repair")

_HUNK = re.compile(r"\+(\d+)(?:,(\d+))?")


def is_work_tree(root: Path) -> bool:
    proc = git(root, "rev-parse", "--is-inside-work-tree", check=False)
    return proc.returncode == 0 and proc.stdout.strip() == "true"


def head_sha(root: Path) -> str:
    return git(root, "rev-parse", "HEAD").stdout.strip()


def dirty_paths(root: Path) -> tuple[str, ...]:
    proc = git(root, "status", "--porcelain", "--untracked-files=all")
    found: list[str] = []
    for line in proc.stdout.splitlines():
        if len(line) < 4:
            continue
        path = _status_path(line)
        if path == ".vibecleaner" or path.startswith(".vibecleaner/"):
            continue
        found.append(path)
    return tuple(found)


def resolve_base(root: Path, requested: str | None) -> str | None:
    """Use an explicit ref, otherwise the merge-base when it is a real diff."""
    if requested:
        proc = git(root, "rev-parse", "--verify", "--quiet", f"{requested}^{{commit}}", check=False)
        if proc.returncode != 0 or not proc.stdout.strip():
            raise GitError(f"unknown git ref {requested}")
        return proc.stdout.strip()
    for name in ("main", "master"):
        if git(root, "rev-parse", "--verify", "--quiet", name, check=False).returncode != 0:
            continue
        proc = git(root, "merge-base", "HEAD", name, check=False)
        if proc.returncode != 0 or not proc.stdout.strip():
            continue
        base = proc.stdout.strip()
        if base == head_sha(root):
            return None
        return base
    return None


def changed_lines(root: Path, base: str | None) -> dict[str, frozenset[int]]:
    if not base:
        return {}
    proc = git(root, "diff", "-U0", base, "--", check=False)
    if proc.returncode != 0:
        raise GitError(proc.stderr.strip() or "git diff failed")
    return _added_lines(proc.stdout)


def changed_paths(root: Path, base: str) -> tuple[str, ...]:
    proc = git(root, "diff", "--name-only", base, "--")
    return tuple(line.strip() for line in proc.stdout.splitlines() if line.strip())


def tree_diff(root: Path, base: str) -> str:
    return git(root, "diff", base, "--").stdout


def add_worktree(root: Path, path: Path, commit: str, *, branch: str | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if branch is None:
        git(root, "worktree", "add", "--detach", str(path), commit)
        return
    git(root, "worktree", "add", "-b", branch, str(path), commit)


def remove_worktree(root: Path, path: Path) -> None:
    proc = git(root, "worktree", "remove", "--force", str(path), check=False)
    if proc.returncode != 0:
        log.warning("could not remove worktree %s: %s", path, proc.stderr.strip())
    git(root, "worktree", "prune", check=False)


def capture_diff(worktree: Path) -> str:
    git(worktree, "add", "-A")
    git(worktree, "reset", "-q", "--", ".vibecleaner", ".pytest_cache", check=False)
    return git(worktree, "diff", "--cached").stdout


def apply_diff(worktree: Path, diff: str) -> None:
    if not diff.strip():
        raise GitError("empty diff")
    proc = git(worktree, "apply", "--whitespace=nowarn", input_text=diff, check=False)
    if proc.returncode != 0:
        raise GitError(proc.stderr.strip() or "git apply failed")


def commit_tree(worktree: Path, message: str) -> str:
    git(worktree, "add", "-A")
    git(worktree, "reset", "-q", "--", ".vibecleaner", ".pytest_cache", check=False)
    status = git(worktree, "diff", "--cached", "--name-only")
    if not status.stdout.strip():
        raise GitError("nothing to commit")
    git(worktree, "commit", "-m", message)
    return head_sha(worktree)


def show_file(root: Path, rev: str, path: str) -> str | None:
    proc = git(root, "show", f"{rev}:{path}", check=False)
    if proc.returncode != 0:
        return None
    return proc.stdout


def _status_path(line: str) -> str:
    path = line[3:].strip()
    if " -> " in path:
        path = path.split(" -> ", 1)[1].strip()
    if len(path) >= 2 and path[0] == path[-1] == '"':
        path = path[1:-1]
    return path.replace("\\", "/")


def _added_lines(diff: str) -> dict[str, frozenset[int]]:
    found: dict[str, set[int]] = {}
    current: str | None = None
    new_line = 0
    for line in diff.splitlines():
        if line.startswith("+++ "):
            path = line[4:]
            if path.startswith("b/"):
                path = path[2:]
            current = None if path == "/dev/null" else path
            if current is not None:
                found.setdefault(current, set())
            continue
        if current is None:
            continue
        if line.startswith("@@"):
            match = _HUNK.search(line)
            new_line = int(match.group(1)) if match else 0
            continue
        if line.startswith("+"):
            if new_line:
                found[current].add(new_line)
            new_line += 1
            continue
        if line.startswith("-") or line.startswith("\\"):
            continue
        new_line += 1
    return {path: frozenset(lines) for path, lines in found.items()}
