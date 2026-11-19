"""Changed-function slices and nearby callers. Stdlib only."""

from __future__ import annotations

import ast
from collections.abc import Mapping
from pathlib import Path

_SKIP = frozenset({".git", ".vibecleaner", "__pycache__", ".pytest_cache", "node_modules", ".venv", "venv"})


def window(text: str, line: int | None, radius: int = 12) -> str:
    rows = text.splitlines()
    if not rows:
        return ""
    if line is None:
        return "\n".join(rows[: 2 * radius])
    start = max(1, line - radius)
    end = min(len(rows), line + radius)
    return "\n".join(rows[start - 1 : end])


def slice_changed(root: Path, changed: Mapping[str, frozenset[int]]) -> str:
    blocks: list[str] = []
    for path, lines in sorted(changed.items()):
        if not path.endswith(".py"):
            continue
        source = _read(root / path)
        if source is None:
            continue
        for name, start, end, body in _python_functions(source):
            if not lines or any(start <= line <= end for line in lines):
                blocks.append(f"# {path}:{start} {name}\n{body}")
        blocks.append(_callers(root, path))
    return "\n\n".join(block for block in blocks if block)


def _read(path: Path) -> str | None:
    if not path.is_file():
        return None
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return None
    except OSError:
        return None


def _python_functions(source: str) -> list[tuple[str, int, int, str]]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    rows = source.splitlines()
    found: list[tuple[str, int, int, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        end = node.end_lineno or node.lineno
        found.append((node.name, node.lineno, end, "\n".join(rows[node.lineno - 1 : end])))
    return found


def _callers(root: Path, path: str) -> str:
    module = Path(path).stem
    hits: list[str] = []
    for file in _python_files(root):
        rel = file.relative_to(root).as_posix()
        if rel == path:
            continue
        text = _read(file)
        if text is None:
            continue
        for index, line in enumerate(text.splitlines(), start=1):
            if f"import {module}" in line or f"from {module} " in line:
                hits.append(f"{rel}:{index}: {line.strip()}")
                if len(hits) >= 8:
                    return "Callers:\n" + "\n".join(hits)
    if not hits:
        return ""
    return "Callers:\n" + "\n".join(hits)


def _python_files(root: Path) -> list[Path]:
    found: list[Path] = []
    for path in root.rglob("*.py"):
        if any(part in _SKIP for part in path.relative_to(root).parts):
            continue
        found.append(path)
        if len(found) >= 200:
            break
    return found

