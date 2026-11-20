"""Detect how to boot a FastAPI, Flask, WSGI, Express, or Next app."""

from __future__ import annotations

import json
import os
import re
import shlex
import sys
from dataclasses import dataclass
from pathlib import Path

_SKIP_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".next",
        ".pytest_cache",
        ".turbo",
        ".venv",
        ".vibeguard",
        "__pycache__",
        "build",
        "coverage",
        "dist",
        "env",
        "node_modules",
        "out",
        "site-packages",
        "test",
        "tests",
        "__tests__",
        "venv",
    }
)
_PREFERRED = {"app.py": 0, "main.py": 1, "server.py": 2, "wsgi.py": 3, "asgi.py": 4}
_FASTAPI = re.compile(r"(?m)(?:^\s*from\s+fastapi\b|^\s*import\s+fastapi\b|FastAPI\s*\()")
_FLASK = re.compile(r"(?m)(?:^\s*from\s+flask\b|^\s*import\s+flask\b|Flask\s*\()")
_ASSIGN = {
    "fastapi": re.compile(r"(?m)^(\w+)\s*=\s*FastAPI\s*\("),
    "flask": re.compile(r"(?m)^(\w+)\s*=\s*Flask\s*\("),
}
_NODE_BINS = frozenset({"node", "nodemon", "ts-node", "tsx"})
_SERVER_MARKERS = ("express(", "createServer(", ".listen(")
_MAX_READ = 500_000


@dataclass(frozen=True)
class AppSpec:
    """A web app the runtime check knows how to boot."""

    kind: str
    root: Path
    entry: Path
    module: str
    attribute: str
    launch: tuple[str, ...] = ()

    def command(self, port: int, *, docker: bool = False) -> tuple[str, ...]:
        python = "python" if docker else sys.executable
        host = "0.0.0.0" if docker else "127.0.0.1"
        if self.kind == "fastapi":
            target = f"{self.module}:{self.attribute}"
            return (python, "-m", "uvicorn", target, "--host", host, "--port", str(port))
        if self.kind == "flask":
            target = f"{self.module}:{self.attribute}"
            return (
                python,
                "-m",
                "flask",
                "--app",
                target,
                "run",
                "--host",
                host,
                "--port",
                str(port),
                "--no-reload",
            )
        if self.kind == "wsgi":
            return (python, self.entry.relative_to(self.root).as_posix())
        if self.kind == "next":
            return ("npx", "--no-install", "next", self.attribute, "-H", host, "-p", str(port))
        return self.launch


def detect_app(root: Path) -> AppSpec | None:
    """Return a boot spec, or None when ``root`` is not a web app."""
    root = Path(root)
    if not root.is_dir():
        return None
    package = _package(root)
    if package is not None:
        spec = _next_spec(root, package)
        if spec is not None:
            return spec
    python = _python_spec(root)
    if python is not None:
        return python
    if package is not None:
        return _node_spec(root, package)
    return None


def _package(root: Path) -> dict | None:
    path = root / "package.json"
    if not path.is_file():
        return None
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(loaded, dict):
        return None
    return loaded


def _scripts(package: dict) -> dict[str, str]:
    raw = package.get("scripts")
    if not isinstance(raw, dict):
        return {}
    return {str(key): value for key, value in raw.items() if isinstance(value, str)}


def _next_spec(root: Path, package: dict) -> AppSpec | None:
    scripts = _scripts(package)
    mode = ""
    for key in ("dev", "start"):
        text = scripts.get(key, "")
        if re.search(r"\bnext\b", text):
            mode = "dev" if re.search(r"\bnext\s+dev\b", text) or key == "dev" else "start"
            break
    if not mode:
        return None
    entry = root / "package.json"
    return AppSpec("next", root, entry, "", mode, ("npx", "--no-install", "next", mode))


def _node_spec(root: Path, package: dict) -> AppSpec | None:
    scripts = _scripts(package)
    if not _node_server(root, package, scripts):
        return None
    for key in ("dev", "start"):
        argv = _node_argv(scripts.get(key, ""))
        if argv is not None:
            entry = root / argv[-1]
            return AppSpec("express", root, entry, "", "app", argv)
    if "start" in scripts:
        return AppSpec("express", root, root / "package.json", "", "app", ("npm", "run", "start"))
    if "dev" in scripts:
        return AppSpec("express", root, root / "package.json", "", "app", ("npm", "run", "dev"))
    return None


def _node_server(root: Path, package: dict, scripts: dict[str, str]) -> bool:
    if not any(key in scripts for key in ("start", "dev")):
        return False
    deps: dict = {}
    for key in ("dependencies", "devDependencies"):
        value = package.get(key)
        if isinstance(value, dict):
            deps.update(value)
    if any(name in deps for name in ("express", "fastify", "koa")):
        return True
    return _tree_contains(root, (".js", ".mjs", ".cjs", ".ts"), _SERVER_MARKERS)


def _node_argv(script: str) -> tuple[str, ...] | None:
    if not script.strip():
        return None
    try:
        parts = shlex.split(script)
    except ValueError:
        return None
    if not parts or Path(parts[0]).name not in _NODE_BINS:
        return None
    files = [part for part in parts[1:] if not part.startswith("-")]
    if not files:
        return None
    return ("node", files[0])


def _python_spec(root: Path) -> AppSpec | None:
    found: dict[str, list[Path]] = {"fastapi": [], "flask": [], "wsgi": []}
    for path in _python_files(root):
        text = _read(path)
        if text is None:
            continue
        if _FASTAPI.search(text):
            found["fastapi"].append(path)
        elif _FLASK.search(text):
            found["flask"].append(path)
        elif "wsgiref" in text and ("make_server" in text or "simple_server" in text):
            found["wsgi"].append(path)
    for kind in ("fastapi", "flask", "wsgi"):
        paths = found[kind]
        if not paths:
            continue
        entry = min(paths, key=lambda item: _rank(item, root))
        text = _read(entry) or ""
        return AppSpec(kind, root, entry, _module_name(root, entry), _attribute(kind, text))
    return None


def _attribute(kind: str, text: str) -> str:
    pattern = _ASSIGN.get(kind)
    if pattern is None:
        return "app"
    match = pattern.search(text)
    if match is None:
        return "app"
    return match.group(1)


def _module_name(root: Path, entry: Path) -> str:
    parts = list(entry.resolve().relative_to(root.resolve()).with_suffix("").parts)
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts) if parts else "app"


def _rank(path: Path, root: Path) -> tuple[int, int, str]:
    rel = path.relative_to(root).as_posix()
    return (_PREFERRED.get(path.name, 10), rel.count("/"), rel)


def _python_files(root: Path) -> list[Path]:
    found: list[Path] = []
    for path in _walk(root):
        if path.suffix == ".py":
            found.append(path)
    return found


def _tree_contains(root: Path, suffixes: tuple[str, ...], markers: tuple[str, ...]) -> bool:
    for path in _walk(root):
        if path.suffix not in suffixes:
            continue
        text = _read(path)
        if text is not None and any(marker in text for marker in markers):
            return True
    return False


def _walk(root: Path) -> list[Path]:
    found: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(name for name in dirnames if name not in _SKIP_DIRS and not name.startswith("."))
        for name in sorted(filenames):
            if name.startswith("."):
                continue
            found.append(Path(dirpath) / name)
    return found


def _read(path: Path) -> str | None:
    try:
        if path.stat().st_size > _MAX_READ:
            return None
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None
