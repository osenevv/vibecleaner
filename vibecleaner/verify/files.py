"""Walk a project tree and classify the files the verifier reads."""

from __future__ import annotations

import os
from pathlib import Path, PurePosixPath

from tree_sitter import Node

from vibecleaner.models import Language, SourceFile
from vibecleaner.ts_parse import parse_root

_SKIP_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".mypy_cache",
        ".next",
        ".pytest_cache",
        ".ruff_cache",
        ".turbo",
        ".venv",
        ".vercel",
        ".vibecleaner",
        "__pycache__",
        "build",
        "coverage",
        "dist",
        "env",
        "node_modules",
        "out",
        "site-packages",
        "venv",
    }
)
_CODE_SUFFIXES = {
    ".cjs": Language.JAVASCRIPT,
    ".cs": Language.CSHARP,
    ".cts": Language.TYPESCRIPT,
    ".js": Language.JAVASCRIPT,
    ".jsx": Language.JAVASCRIPT,
    ".mjs": Language.JAVASCRIPT,
    ".mts": Language.TYPESCRIPT,
    ".py": Language.PYTHON,
    ".pyi": Language.PYTHON,
    ".ts": Language.TYPESCRIPT,
    ".tsx": Language.TSX,
}
_CONFIG_NAMES = frozenset(
    {
        ".coveragerc",
        ".eslintrc",
        ".eslintrc.cjs",
        ".eslintrc.js",
        ".eslintrc.json",
        ".eslintrc.yaml",
        ".eslintrc.yml",
        ".ruff.toml",
        "eslint.config.cjs",
        "eslint.config.js",
        "eslint.config.mjs",
        "eslint.config.ts",
        "jest.config.cjs",
        "jest.config.js",
        "jest.config.mjs",
        "jest.config.ts",
        "mypy.ini",
        "package.json",
        "pyproject.toml",
        "pyrightconfig.json",
        "pytest.ini",
        "requirements.txt",
        "ruff.toml",
        "setup.cfg",
        "setup.py",
        "tox.ini",
        "tsconfig.build.json",
        "tsconfig.json",
        "vitest.config.js",
        "vitest.config.mjs",
        "vitest.config.ts",
    }
)
_MAX_BYTES = 1024 * 1024
_BINARY_PROBE = 8192


def iter_files(root: Path):
    """Yield ``(relative posix path, absolute path)`` for files under ``root``."""
    base = root.resolve()
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = sorted(name for name in dirnames if name not in _SKIP_DIRS)
        for name in sorted(filenames):
            path = Path(dirpath) / name
            if not _inside(base, path):
                continue
            yield path.relative_to(base).as_posix(), path


def language_for(rel: str) -> Language | None:
    return _CODE_SUFFIXES.get(PurePosixPath(rel).suffix.lower())


def is_test_path(rel: str) -> bool:
    path = PurePosixPath(rel)
    if any(part in {"tests", "test", "__tests__"} for part in path.parts):
        return True
    name = path.name
    if name == "conftest.py" or name.endswith("_test.py"):
        return True
    if name.startswith("test_") and name.endswith(".py"):
        return True
    if name.endswith(("Tests.cs", "Test.cs")):
        return True
    stem = path.stem
    return stem.endswith(".test") or stem.endswith(".spec")


def is_config_path(rel: str) -> bool:
    name = PurePosixPath(rel).name
    if name in _CONFIG_NAMES:
        return True
    if name.endswith((".csproj", ".sln")) or name in {"Directory.Build.props", "Directory.Packages.props", "global.json", "nuget.config"}:
        return True
    return name.startswith((".eslintrc", "jest.config.", "vitest.config.", "tsconfig.", "requirements"))


def is_code_path(rel: str) -> bool:
    return language_for(rel) is not None


def has_code(root: Path) -> bool:
    for rel, _path in iter_files(root):
        if is_code_path(rel):
            return True
    return False


def project_runtimes(root: Path) -> frozenset[str]:
    """Languages whose toolchain this tree needs inside the sandbox."""
    found: set[str] = set()
    if (root / "package.json").is_file():
        found.add("node")
    if any((root / name).is_file() for name in ("pyproject.toml", "setup.py", "setup.cfg")):
        found.add("python")
    if any(root.glob("requirements*.txt")):
        found.add("python")
    if (root / "go.mod").is_file():
        found.add("go")
    if (root / "Cargo.toml").is_file():
        found.add("rust")
    if any((root / name).is_file() for name in ("pom.xml", "build.gradle", "build.gradle.kts")):
        found.add("jvm")
    if any(root.glob("*.csproj")) or any(root.glob("*.sln")) or any(root.glob("*/*.csproj")):
        found.add("csharp")
    for rel, _path in iter_files(root):
        language = language_for(rel)
        if language == Language.PYTHON:
            found.add("python")
        elif language in {Language.TYPESCRIPT, Language.TSX, Language.JAVASCRIPT}:
            found.add("node")
        elif language == Language.CSHARP:
            found.add("csharp")
        elif rel.endswith(".go"):
            found.add("go")
        elif rel.endswith(".rs"):
            found.add("rust")
        elif rel.endswith((".java", ".kt", ".kts")):
            found.add("jvm")
    return frozenset(found)


def read_text(path: Path) -> str | None:
    try:
        if path.stat().st_size > _MAX_BYTES:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    if b"\0" in data[:_BINARY_PROBE]:
        return None
    return data.decode("utf-8", errors="replace")


def source_from(rel: str, text: str) -> SourceFile | None:
    language = language_for(rel)
    if language is None:
        return None
    return SourceFile(path=rel, abs_path=Path(rel), language=language, text=text)


def parsed(rel: str, text: str) -> tuple[SourceFile, Node] | None:
    source = source_from(rel, text)
    if source is None:
        return None
    root = parse_root(source)
    if root is None:
        return None
    return source, root


def line_of(node: Node) -> int:
    return node.start_point[0] + 1


def _inside(root: Path, path: Path) -> bool:
    try:
        path.resolve().relative_to(root)
    except (OSError, ValueError):
        return False
    return True
