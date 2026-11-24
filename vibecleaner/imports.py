"""Imports whose distribution is not declared by the project."""

from __future__ import annotations

import ast
import json
import re
import sys
from pathlib import Path, PurePosixPath

from vibecleaner.deslop import _is_test_path
from vibecleaner.models import Finding, Language, SourceFile

__all__ = ["missing_imports"]

# Import name -> distribution names that satisfy it.
_PY_MODULE_ALIASES = {"google.genai": "google-genai"}
_PY_ALIASES: dict[str, frozenset[str]] = {
    "pil": frozenset({"pillow"}),
    "cv2": frozenset({"opencv-python", "opencv-python-headless"}),
    "yaml": frozenset({"pyyaml"}),
    "sklearn": frozenset({"scikit-learn"}),
    "bs4": frozenset({"beautifulsoup4"}),
    "attr": frozenset({"attrs"}),
    "dotenv": frozenset({"python-dotenv"}),
    "dateutil": frozenset({"python-dateutil"}),
    "gi": frozenset({"pygobject"}),
    "opengl": frozenset({"pyopengl"}),
}
_JS_BUILTINS = frozenset(
    {
        "assert",
        "buffer",
        "child_process",
        "cluster",
        "console",
        "constants",
        "crypto",
        "dgram",
        "dns",
        "domain",
        "events",
        "fs",
        "http",
        "http2",
        "https",
        "inspector",
        "module",
        "net",
        "os",
        "path",
        "perf_hooks",
        "process",
        "punycode",
        "querystring",
        "readline",
        "repl",
        "stream",
        "string_decoder",
        "timers",
        "tls",
        "trace_events",
        "tty",
        "url",
        "util",
        "v8",
        "vm",
        "wasi",
        "worker_threads",
        "zlib",
        "async_hooks",
        "diagnostics_channel",
        "http2",
        "inspector",
        "quic",
        "sqlite",
        "test",
        "timers/promises",
        "stream/promises",
        "fs/promises",
    }
)
_JS_IMPORT = re.compile(
    r"""(?:import\s+(?:[^'"\n]+?\s+from\s+)?|export\s+[^'"\n]+?\s+from\s+|require\(\s*)['"]([^'"]+)['"]"""
)
_GO_IMPORT = re.compile(r'^\s*(?:[\w.]+\s+)?"([^"]+)"\s*$', re.MULTILINE)
_DEP_NAME = re.compile(r"^([A-Za-z0-9_.-]+)")
_GO_REQUIRE = re.compile(r"^\s*([^\s]+)\s+v", re.MULTILINE)


def missing_imports(root: Path, files: list[SourceFile]) -> list[Finding]:
    """Flag an import the manifest does not declare and the tree does not contain."""
    root = Path(root)
    has_python = (root / "pyproject.toml").is_file() or (root / "requirements.txt").is_file()
    has_node = (root / "package.json").is_file()
    has_go = (root / "go.mod").is_file()
    python = _python_declared(root) if has_python else set()
    javascript = _node_declared(root) if has_node else set()
    gomodule, gorequire = _go_declared(root) if has_go else ("", set())
    local_py = _local_python(files)
    local_js = _local_javascript(files)
    found: list[Finding] = []
    for source in files:
        if _is_test_path(source.path):
            continue
        if source.language == Language.PYTHON and has_python:
            found.extend(_python_file(source, python, local_py))
        elif source.language in {Language.JAVASCRIPT, Language.TYPESCRIPT, Language.TSX} and has_node:
            found.extend(_javascript_file(source, javascript, local_js))
        elif PurePosixPath(source.path).suffix.lower() == ".go" and has_go:
            found.extend(_go_file(source, gomodule, gorequire))
    return found


def _python_file(source: SourceFile, declared: set[str], local: set[str]) -> list[Finding]:
    try:
        tree = ast.parse(source.text)
    except SyntaxError:
        return []
    parents: dict[ast.AST, ast.AST] = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[child] = node
    found: list[Finding] = []
    seen: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules = [(alias.name, node.lineno) for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            modules = [(node.module, node.lineno)]
            if node.module == "google" and any(alias.name == "genai" for alias in node.names):
                modules = [("google.genai", node.lineno)]
        else:
            continue
        if _optional_import(node, parents):
            continue
        for module, line in modules:
            alias = _module_alias(module)
            if alias is not None and _normalize_dist(alias) in declared:
                continue
            root_name = module.split(".", 1)[0]
            if root_name in seen or _python_ok(root_name, declared, local):
                continue
            seen.add(root_name)
            found.append(
                Finding(
                    rule_id="D9.missing_dependency",
                    file=source.path,
                    line=line,
                    message=f"Python import {root_name} is not in the project manifest",
                    symbol=root_name,
                )
            )
    return found


def _module_alias(module: str) -> str | None:
    for name, dist in _PY_MODULE_ALIASES.items():
        if module == name or module.startswith(name + "."):
            return dist
    return None


def _optional_import(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> bool:
    current: ast.AST | None = node
    while current is not None:
        if isinstance(current, ast.If) and isinstance(current.test, ast.Name) and current.test.id == "TYPE_CHECKING":
            return True
        if isinstance(current, ast.Try):
            for handler in current.handlers:
                if _catches_import(handler.type):
                    return True
        current = parents.get(current)
    return False


def _catches_import(node: ast.AST | None) -> bool:
    if node is None:
        return True
    if isinstance(node, ast.Name):
        return node.id in {"ImportError", "ModuleNotFoundError"}
    if isinstance(node, ast.Tuple):
        return any(_catches_import(item) for item in node.elts)
    return False


def _python_ok(name: str, declared: set[str], local: set[str]) -> bool:
    folded = name.casefold().replace("_", "-")
    if name in sys.stdlib_module_names or name in local:
        return True
    if folded in declared:
        return True
    aliases = _PY_ALIASES.get(name.casefold(), ())
    return any(alias.casefold() in declared for alias in aliases)


def _javascript_file(source: SourceFile, declared: set[str], local: set[str]) -> list[Finding]:
    found: list[Finding] = []
    seen: set[str] = set()
    for index, line in enumerate(source.text.splitlines(), start=1):
        for match in _JS_IMPORT.finditer(line):
            spec = match.group(1)
            if spec.startswith(".") or spec.startswith("@/") or spec.startswith("~/"):
                continue
            package = _node_package(spec)
            if package in seen or package in _JS_BUILTINS or package in local or package.casefold() in declared:
                continue
            if package.startswith("node:"):
                continue
            seen.add(package)
            found.append(
                Finding(
                    rule_id="D9.missing_dependency",
                    file=source.path,
                    line=index,
                    message=f"JavaScript import {package} is not in package.json",
                    symbol=package,
                )
            )
    return found


def _node_package(spec: str) -> str:
    if spec.startswith("@"):
        parts = spec.split("/")
        return "/".join(parts[:2]) if len(parts) >= 2 else spec
    return spec.split("/", 1)[0]


def _go_file(source: SourceFile, module: str, required: set[str]) -> list[Finding]:
    found: list[Finding] = []
    seen: set[str] = set()
    for index, line in enumerate(source.text.splitlines(), start=1):
        match = _GO_IMPORT.match(line)
        if match is None:
            continue
        path = match.group(1)
        if _go_ok(path, module, required) or path in seen:
            continue
        seen.add(path)
        found.append(
            Finding(
                rule_id="D9.missing_dependency",
                file=source.path,
                line=index,
                message=f"Go import {path} is not in go.mod",
                symbol=path,
            )
        )
    return found


def _go_ok(path: str, module: str, required: set[str]) -> bool:
    if "/" not in path:
        return True
    if module and (path == module or path.startswith(module + "/")):
        return True
    return any(path == item or path.startswith(item + "/") for item in required)


def _local_python(files: list[SourceFile]) -> set[str]:
    names: set[str] = set()
    for source in files:
        pure = PurePosixPath(source.path)
        if pure.suffix.lower() != ".py":
            continue
        parts = list(pure.parts)
        if parts and parts[0] in {"src", "lib"}:
            parts = parts[1:]
        if not parts:
            continue
        if parts[-1] == "__init__.py" and len(parts) >= 2:
            names.add(parts[0])
        elif len(parts) == 1:
            names.add(pure.stem)
        else:
            names.add(parts[0])
    return names


def _local_javascript(files: list[SourceFile]) -> set[str]:
    names: set[str] = set()
    for source in files:
        pure = PurePosixPath(source.path)
        if pure.suffix.lower() not in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}:
            continue
        parts = list(pure.parts)
        if parts and parts[0] in {"src", "lib", "app"}:
            parts = parts[1:]
        if parts:
            names.add(parts[0].split(".", 1)[0])
    return names


def _python_declared(root: Path) -> set[str]:
    declared: set[str] = set()
    project = root / "pyproject.toml"
    if project.is_file():
        declared.update(_toml_deps(project.read_text(encoding="utf-8")))
    requirements = root / "requirements.txt"
    if requirements.is_file():
        for line in requirements.read_text(encoding="utf-8").splitlines():
            name = _dep_name(line)
            if name:
                declared.add(name)
    return declared


def _toml_deps(text: str) -> set[str]:
    try:
        import tomllib
    except ImportError:
        return _toml_deps_fallback(text)
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return _toml_deps_fallback(text)
    names: set[str] = set()
    project = data.get("project")
    if isinstance(project, dict):
        deps = project.get("dependencies")
        if isinstance(deps, list):
            names.update(_dep_name(str(item)) for item in deps if isinstance(item, str))
        optional = project.get("optional-dependencies")
        if isinstance(optional, dict):
            for group in optional.values():
                if isinstance(group, list):
                    names.update(_dep_name(str(item)) for item in group if isinstance(item, str))
    tool = data.get("tool")
    if isinstance(tool, dict):
        poetry = tool.get("poetry")
        if isinstance(poetry, dict):
            for key in ("dependencies", "dev-dependencies"):
                block = poetry.get(key)
                if isinstance(block, dict):
                    for dep in block:
                        if dep.casefold() != "python":
                            names.add(_normalize_dist(dep))
    return {name for name in names if name}


def _toml_deps_fallback(text: str) -> set[str]:
    names: set[str] = set()
    section = ""
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped
            continue
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key_clean = key.strip()
        if section == "[project]" and key_clean == "dependencies":
            names.update(_quoted_deps(value))
        elif section.startswith("[project.optional-dependencies"):
            names.update(_quoted_deps(value))
        elif section == "[tool.poetry.dependencies]" and key_clean.casefold() != "python":
            names.add(_normalize_dist(key_clean))
    for match in re.finditer(r"(?m)^dependencies\s*=\s*\[(.*?)\]", text, re.S):
        names.update(_quoted_deps(match.group(1)))
    return {name for name in names if name}


def _quoted_deps(text: str) -> set[str]:
    return {_dep_name(match) for match in re.findall(r"""['"]([^'"]+)['"]""", text) if _dep_name(match)}


def _dep_name(spec: str) -> str:
    spec = spec.split("#", 1)[0].strip()
    if not spec or spec.startswith("-"):
        return ""
    match = _DEP_NAME.match(spec)
    if match is None:
        return ""
    return _normalize_dist(match.group(1))


def _normalize_dist(name: str) -> str:
    return name.strip().casefold().replace("_", "-")


def _node_declared(root: Path) -> set[str]:
    path = root / "package.json"
    if not path.is_file():
        return set()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return set()
    declared: set[str] = set()
    if isinstance(data, dict):
        for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
            block = data.get(key)
            if isinstance(block, dict):
                declared.update(name.casefold() for name in block)
    return declared


def _go_declared(root: Path) -> tuple[str, set[str]]:
    path = root / "go.mod"
    if not path.is_file():
        return "", set()
    text = path.read_text(encoding="utf-8")
    module = ""
    for line in text.splitlines():
        if line.startswith("module "):
            module = line.split(None, 1)[1].strip()
            break
    return module, set(_GO_REQUIRE.findall(text))
