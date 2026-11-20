"""Changed-line maps and source-file helpers for the probe nodes."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path, PurePosixPath

from vibeguard.models import Language, SourceFile

ChangedLines = Mapping[str, frozenset[int]]

_SKIP_PARTS = frozenset(
    {
        ".git",
        ".venv",
        "venv",
        "node_modules",
        "__pycache__",
        ".vibeguard",
        ".pytest_cache",
        ".hypothesis",
        ".mypy_cache",
        ".ruff_cache",
        "dist",
        "build",
        ".tox",
        ".nox",
    }
)
_TEST_PARTS = frozenset({"tests", "__tests__", "fixtures"})
_SUFFIXES = {
    ".py": Language.PYTHON,
    ".ts": Language.TYPESCRIPT,
    ".tsx": Language.TSX,
    ".js": Language.JAVASCRIPT,
    ".mjs": Language.JAVASCRIPT,
    ".cjs": Language.JAVASCRIPT,
    ".jsx": Language.TSX,
}


def normalize_changed(cwd: Path, changed: ChangedLines) -> dict[str, frozenset[int]]:
    root = cwd.resolve()
    normalized: dict[str, frozenset[int]] = {}
    for raw, lines in changed.items():
        rel = _relative(root, raw)
        if rel is None:
            continue
        numbers = frozenset(line for line in lines if isinstance(line, int) and line > 0)
        if numbers:
            normalized[rel] = numbers
    return normalized


def is_skipped_path(rel: str) -> bool:
    pure = PurePosixPath(rel)
    if any(part in _SKIP_PARTS or part in _TEST_PARTS for part in pure.parts):
        return True
    name = pure.name
    if name == "conftest.py" or name.startswith("test_") or name.endswith("_test.py"):
        return True
    if name.endswith(".d.ts"):
        return True
    return ".test." in name or ".spec." in name


def overlaps(start: int, end: int, lines: frozenset[int]) -> bool:
    return any(start <= line <= end for line in lines)


def language_of(rel: str) -> Language | None:
    return _SUFFIXES.get(PurePosixPath(rel).suffix.lower())


def as_source_file(rel: str, text: str) -> SourceFile | None:
    language = language_of(rel)
    if language is None:
        return None
    return SourceFile(path=rel, abs_path=Path(rel), language=language, text=text)


def read_text(cwd: Path, rel: str) -> str | None:
    path = cwd / rel
    if not path.is_file():
        return None
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return None


def _relative(root: Path, raw: str) -> str | None:
    path = Path(raw)
    if path.is_absolute():
        try:
            return path.resolve().relative_to(root).as_posix()
        except ValueError:
            return None
    text = raw.replace("\\", "/")
    if text.startswith("./"):
        text = text[2:]
    if not text or ".." in PurePosixPath(text).parts:
        return None
    return PurePosixPath(text).as_posix()
