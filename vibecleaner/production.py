"""Production gaps: supply chain, lifecycle, contracts, tests, and hygiene."""

from __future__ import annotations

import ast
import json
import os
import re
from pathlib import Path, PurePosixPath

from vibecleaner.deslop import _is_test_path
from vibecleaner.imports import _go_declared, _node_declared, _python_declared
from vibecleaner.models import Finding, Language, SourceFile

__all__ = ["production_findings", "suppress"]

_POPULAR = frozenset(
    {
        "aiohttp",
        "axios",
        "boto3",
        "celery",
        "click",
        "cryptography",
        "django",
        "express",
        "fastapi",
        "flask",
        "httpx",
        "jinja2",
        "lodash",
        "next",
        "numpy",
        "pandas",
        "pydantic",
        "pytest",
        "react",
        "redis",
        "requests",
        "sqlalchemy",
        "starlette",
        "typescript",
        "uvicorn",
        "vue",
        "webpack",
        "angular",
        "black",
        "boto",
        "certifi",
        "charset-normalizer",
        "dateutil",
        "ecdsa",
        "gunicorn",
        "idna",
        "itsdangerous",
        "mako",
        "markupsafe",
        "mypy",
        "orjson",
        "packaging",
        "pillow",
        "pip",
        "pluggy",
        "protobuf",
        "pyjwt",
        "pyyaml",
        "rich",
        "ruff",
        "setuptools",
        "six",
        "tomli",
        "typing-extensions",
        "urllib3",
        "werkzeug",
        "wheel",
        "wrapt",
        "yarl",
    }
)
_SECRET_WORD = re.compile(r"token|password|secret|nonce|otp|session|api[_-]?key", re.I)
_WEAK_HASH = re.compile(r"hashlib\.(?:md5|sha1)\b|\bMD5\b|\bSHA1\b")
_WEAK_RANDOM = re.compile(r"\brandom\.(?:random|randint|randrange|choice)\b|Math\.random\s*\(")
_OPEN = re.compile(r"(?<![\w.])open\s*\(")
_INTERVAL = re.compile(r"\bsetInterval\s*\(")
_CLEAR = re.compile(r"\bclearInterval\s*\(")
_HTTP = re.compile(
    r"\b(?:requests|httpx)\.(?:get|post|put|patch|delete|head|request)\s*\(|\bfetch\s*\(|\burllib\.request\.urlopen\s*\("
)
_DROP = re.compile(r"\bDROP\s+(?:COLUMN|TABLE)\b", re.I)
_INDEX = re.compile(r"\bCREATE\s+(?:UNIQUE\s+)?INDEX\b", re.I)
_CONCURRENT = re.compile(r"\bCONCURRENTLY\b", re.I)
_ENV_USE = re.compile(
    r"""os\.environ\[\s*['"]([A-Z][A-Z0-9_]+)['"]\]|os\.environ(?:\.get)?\(\s*['"]([A-Z][A-Z0-9_]+)['"]|os\.getenv\(\s*['"]([A-Z][A-Z0-9_]+)['"]|process\.env\.([A-Z][A-Z0-9_]+)|process\.env\[\s*['"]([A-Z][A-Z0-9_]+)['"]\]"""
)
_ENV_KEY = re.compile(r"^([A-Z][A-Z0-9_]+)=")
_ROUTE = re.compile(
    r"""@(?:app|router|bp)\.(get|post|put|patch|delete)\(\s*['"]([^'"]+)['"]|(?<![.\w])app\.(get|post|put|patch|delete)\(\s*['"]([^'"]+)['"]"""
)
_PROMPT = re.compile(
    r"as an ai language model|as a large language model|you are a helpful assistant|certainly! here|my training data|i cannot browse|let me know if you'd like me",
    re.I,
)
_TAUTOLOGY = re.compile(
    r"""assert\s+True\b|assert\s+1\s*==\s*1\b|expect\(\s*true\s*\)\.toBe\(\s*true\s*\)|expect\(\s*1\s*\)\.toBe\(\s*1\s*\)"""
)
_IGNORE = re.compile(r"unslop-ignore(?:\s*:?\s*([A-Z][A-Z0-9_.]*))?", re.I)


def production_findings(root: Path, files: list[SourceFile]) -> list[Finding]:
    """Layer 1 findings for the production gaps that are still mechanical."""
    root = Path(root)
    found: list[Finding] = []
    found.extend(_weak_crypto(files))
    found.extend(_slopsquat(root))
    found.extend(_sinks(files))
    found.extend(_leaks(files))
    found.extend(_races(files))
    found.extend(_timeouts(files))
    found.extend(_contracts(root, files))
    found.extend(_migrations(files))
    found.extend(_env_parity(root, files))
    found.extend(_tests(files))
    found.extend(_prompts(files))
    found.extend(_telemetry(files))
    found.extend(_loop_io(files))
    found.extend(_boundary(files))
    found.extend(_graphql(root, files))
    found.extend(_registry(root))
    found.extend(_advisories(root))
    return found


def suppress(files: list[SourceFile], findings: list[Finding]) -> list[Finding]:
    """Drop a finding whose line, or the line above it, says unslop-ignore."""
    text = {source.path: source.text for source in files}
    kept: list[Finding] = []
    for finding in findings:
        if _ignored(text.get(finding.file, ""), finding.line, finding.rule_id):
            continue
        kept.append(finding)
    return kept


def _ignored(source: str, line: int, rule_id: str) -> bool:
    rows = source.splitlines()
    window = []
    if 1 <= line <= len(rows):
        window.append(rows[line - 1])
    if line > 1:
        window.append(rows[line - 2])
    for row in window:
        match = _IGNORE.search(row)
        if match is None:
            continue
        named = match.group(1)
        if named is None or named == rule_id:
            return True
    return False


def _hit(rule_id: str, source: SourceFile, line: int, message: str) -> Finding:
    return Finding(rule_id=rule_id, file=source.path, line=line, message=message)


def _weak_crypto(files: list[SourceFile]) -> list[Finding]:
    found: list[Finding] = []
    for source in files:
        if _is_test_path(source.path):
            continue
        if source.language == Language.PYTHON:
            found.extend(_python_crypto(source))
            continue
        for index, line in enumerate(source.text.splitlines(), start=1):
            if _WEAK_RANDOM.search(line) and _SECRET_WORD.search(line):
                found.append(_hit("D1.weak_crypto", source, index, "A secret is drawn from a weak random source"))
    return found


def _python_crypto(source: SourceFile) -> list[Finding]:
    try:
        tree = ast.parse(source.text)
    except SyntaxError:
        return []
    found: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        label = _call_name(node.func)
        if label in {"hashlib.md5", "hashlib.sha1"} or _weak_hash_factory(node):
            found.append(_hit("D1.weak_crypto", source, node.lineno, "MD5 or SHA-1 is not a secure fingerprint"))
        if _ecb_or_des(node, label):
            found.append(_hit("D1.weak_crypto", source, node.lineno, "DES, RC4, or ECB mode is a weak construction"))
        if label in {"random.random", "random.randint", "random.randrange", "random.choice"}:
            segment = ast.get_source_segment(source.text, node) or ""
            if _SECRET_WORD.search(segment):
                found.append(_hit("D1.weak_crypto", source, node.lineno, "A secret is drawn from a weak random source"))
    return found


def _slopsquat(root: Path) -> list[Finding]:
    names = _python_declared(root) | _node_declared(root) | {name.split("/")[-1] for name in _go_declared(root)[1]}
    found: list[Finding] = []
    for name in sorted(names):
        if len(name) < 6 or name in _POPULAR:
            continue
        twin = next((popular for popular in _POPULAR if _distance(name, popular) == 1), "")
        if not twin:
            continue
        found.append(
            Finding(
                rule_id="D9.slopsquat",
                file="pyproject.toml" if (root / "pyproject.toml").is_file() else "package.json",
                line=1,
                message=f"Dependency {name} is one edit from {twin}",
                symbol=name,
            )
        )
    return found


def _distance(left: str, right: str) -> int:
    """Damerau-Levenshtein, capped. A transposition of two letters is one edit."""
    if abs(len(left) - len(right)) > 1:
        return 2
    rows = len(left) + 1
    cols = len(right) + 1
    grid = [[0] * cols for _ in range(rows)]
    for i in range(rows):
        grid[i][0] = i
    for j in range(cols):
        grid[0][j] = j
    for i, char in enumerate(left, start=1):
        for j, other in enumerate(right, start=1):
            cost = char != other
            grid[i][j] = min(grid[i - 1][j] + 1, grid[i][j - 1] + 1, grid[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and left[i - 1] == right[j - 2] and left[i - 2] == right[j - 1]:
                grid[i][j] = min(grid[i][j], grid[i - 2][j - 2] + 1)
    return grid[-1][-1]


_STATIC_INNER_HTML = re.compile(r"""\.innerHTML\s*=\s*(?:'[^']*'|"[^"]*"|`[^`$]*`)\s*;?\s*$""")
_ALL_CAPS = re.compile(r"^[A-Z][A-Z0-9_]+$")


_DOC_SUFFIXES = frozenset({".md", ".mdx", ".rst", ".txt"})


def _sinks(files: list[SourceFile]) -> list[Finding]:
    found: list[Finding] = []
    for source in files:
        if _is_test_path(source.path) or Path(source.path).suffix.lower() in _DOC_SUFFIXES:
            continue
        if source.language == Language.PYTHON:
            found.extend(_python_sinks(source))
            continue
        for index, line in enumerate(source.text.splitlines(), start=1):
            if line.lstrip().startswith(("'", '"', "`")):
                continue
            if "dangerouslySetInnerHTML" in line:
                found.append(_hit("D5.unsafe_sink", source, index, "Raw HTML is rendered from data"))
            elif re.search(r"\.innerHTML\s*=", line) and not _STATIC_INNER_HTML.search(line):
                found.append(_hit("D5.unsafe_sink", source, index, "Raw HTML is rendered from data"))
    return found


def _is_const_literal_dict(node: ast.AST) -> bool:
    if not isinstance(node, ast.Dict):
        return False
    for k, v in zip(node.keys, node.values):
        if not (isinstance(k, ast.Constant) and isinstance(k.value, str)):
            return False
        if isinstance(v, ast.Constant) and isinstance(v.value, str):
            continue
        if _is_const_literal_dict(v):
            continue
        return False
    return True


def _is_safe_placeholder_expr(node: ast.AST, safe_names: set[str]) -> bool:
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, ast.Name):
        return bool(_ALL_CAPS.match(node.id)) or node.id in safe_names
    if isinstance(node, ast.IfExp):
        return _is_safe_placeholder_expr(node.body, safe_names) and _is_safe_placeholder_expr(node.orelse, safe_names)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _is_safe_placeholder_expr(node.left, safe_names) and _is_safe_placeholder_expr(node.right, safe_names)
    if isinstance(node, ast.JoinedStr):
        return all(
            isinstance(part, ast.Constant)
            or (isinstance(part, ast.FormattedValue) and _is_safe_placeholder_expr(part.value, safe_names))
            for part in node.values
        )
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "join"
        and isinstance(node.func.value, ast.Constant)
        and isinstance(node.func.value.value, str)
        and len(node.args) == 1
    ):
        arg = node.args[0]
        if isinstance(arg, ast.Name) and arg.id in safe_names:
            return True
        if isinstance(arg, ast.GeneratorExp) and isinstance(arg.elt, ast.Constant) and arg.elt.value == "?":
            return True
        if (
            isinstance(arg, ast.BinOp)
            and isinstance(arg.op, ast.Mult)
            and isinstance(arg.left, (ast.List, ast.Tuple))
            and len(arg.left.elts) == 1
            and isinstance(arg.left.elts[0], ast.Constant)
            and arg.left.elts[0].value == "?"
        ):
            return True
    return False


def _collect_safe_sql_locals(fn: ast.AST) -> set[str]:
    """Collect local variable names in ``fn`` that are only ever assigned static SQL fragments or '?' placeholders."""
    assigned: dict[str, list[ast.AST]] = {}
    list_elems: dict[str, list[ast.AST]] = {}
    dict_iter_safe: set[str] = set()

    for node in ast.walk(fn):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    assigned.setdefault(target.id, []).append(node.value)
                    if _is_const_literal_dict(node.value):
                        dict_iter_safe.add(target.id)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value is not None:
            assigned.setdefault(node.target.id, []).append(node.value)
            if _is_const_literal_dict(node.value):
                dict_iter_safe.add(node.target.id)
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "append"
            and isinstance(node.func.value, ast.Name)
            and len(node.args) == 1
        ):
            list_elems.setdefault(node.func.value.id, []).append(node.args[0])
        elif isinstance(node, ast.For):
            # Iterating over a constant dict of string literals (e.g. schema migrations).
            if (
                isinstance(node.iter, ast.Call)
                and isinstance(node.iter.func, ast.Attribute)
                and node.iter.func.attr in {"items", "keys", "values"}
                and isinstance(node.iter.func.value, ast.Name)
                and node.iter.func.value.id in dict_iter_safe
            ):
                if isinstance(node.target, ast.Tuple):
                    for elt in node.target.elts:
                        if isinstance(elt, ast.Name):
                            dict_iter_safe.add(elt.id)
                elif isinstance(node.target, ast.Name):
                    dict_iter_safe.add(node.target.id)

    safe: set[str] = set(dict_iter_safe)
    # Fixed-point propagation for simple safe lists and safe string fragments.
    for _ in range(3):
        for name, values in assigned.items():
            if name in safe:
                continue
            # List of static SQL clauses (e.g. clauses = ["profile_id=?"]; clauses.append("status=?"))
            if len(values) == 1 and isinstance(values[0], ast.List):
                init_ok = all(_is_safe_placeholder_expr(e, safe) for e in values[0].elts)
                appends_ok = all(_is_safe_placeholder_expr(e, safe) for e in list_elems.get(name, ()))
                if init_ok and appends_ok:
                    safe.add(name)
                    continue
            if values and all(_is_safe_placeholder_expr(v, safe) for v in values):
                safe.add(name)
    return safe


def _python_sinks(source: SourceFile) -> list[Finding]:
    try:
        tree = ast.parse(source.text)
    except SyntaxError:
        return []
    found: list[Finding] = []
    # Map each call node to its enclosing function's safe SQL locals.
    safe_by_call: dict[int, set[str]] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            safe_locals = _collect_safe_sql_locals(node)
            for child in ast.walk(node):
                if isinstance(child, ast.Call):
                    safe_by_call[id(child)] = safe_locals
    module_safe = _collect_safe_sql_locals(tree)

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        label = _call_name(node.func)
        if label in {"pickle.load", "pickle.loads"}:
            found.append(_hit("D5.unsafe_sink", source, node.lineno, "pickle load can run code from the payload"))
        if label == "yaml.load" and not any(_keyword_name(item) == "Loader" for item in node.keywords):
            found.append(_hit("D5.unsafe_sink", source, node.lineno, "yaml.load without SafeLoader executes tags"))
        if label == "os.system" or _shell_true(node, label):
            found.append(_hit("D5.unsafe_sink", source, node.lineno, "A shell is started from a string"))
        if label.endswith(".execute") and node.args and isinstance(node.args[0], (ast.JoinedStr, ast.BinOp)):
            safe_names = safe_by_call.get(id(node), module_safe)
            if not _is_safe_placeholder_expr(node.args[0], safe_names):
                found.append(_hit("D5.unsafe_sink", source, node.lineno, "SQL is built by string interpolation"))
        if label in {"eval", "exec"}:
            found.append(_hit("D5.unsafe_sink", source, node.lineno, "eval or exec runs a string as code"))
    return found


def _shell_true(node: ast.Call, label: str) -> bool:
    if not label.startswith("subprocess."):
        return False
    return any(_keyword_name(item) == "shell" and isinstance(item.value, ast.Constant) and item.value.value is True for item in node.keywords)


def _keyword_name(node: ast.keyword) -> str:
    return node.arg or ""


def _leaks(files: list[SourceFile]) -> list[Finding]:
    found: list[Finding] = []
    for source in files:
        if _is_test_path(source.path):
            continue
        lines = source.text.splitlines()
        if re.search(r"\bsocket\.socket\s*\(", source.text) and ".close(" not in source.text:
            found.append(_hit("D8.resource_leak", source, 1, "A socket is opened and this file never closes one"))
        if re.search(r"\baddEventListener\s*\(", source.text) and "removeEventListener" not in source.text:
            found.append(_hit("D8.resource_leak", source, 1, "An event listener is added and never removed"))
        if _INTERVAL.search(source.text) and not _CLEAR.search(source.text):
            for index, line in enumerate(lines, start=1):
                if _INTERVAL.search(line):
                    found.append(_hit("D8.resource_leak", source, index, "setInterval has no clearInterval in this file"))
                    break
        for index, line in enumerate(lines, start=1):
            if not _OPEN.search(line) or "with " in line:
                continue
            if re.search(r"=\s*open\s*\(", line) or line.strip().startswith("open("):
                found.append(_hit("D8.resource_leak", source, index, "open() is not inside a with statement"))
    return found


def _races(files: list[SourceFile]) -> list[Finding]:
    found: list[Finding] = []
    for source in files:
        if source.language != Language.PYTHON or _is_test_path(source.path):
            continue
        try:
            tree = ast.parse(source.text)
        except SyntaxError:
            continue
        targets = _thread_targets(tree)
        for node in ast.walk(tree):
            if isinstance(node, ast.AsyncFunctionDef):
                where = f"async {node.name}"
            elif isinstance(node, ast.FunctionDef) and node.name in targets:
                where = f"thread target {node.name}"
            else:
                continue
            segment = ast.get_source_segment(source.text, node) or ""
            if re.search(r"\block\b", segment, re.I):
                continue
            read_modify = re.search(
                r"if\s+\w+\s+not in\s+(\w+)\s*:\s*\n(?:[ \t]+.*\n){0,6}[ \t]+(?:await\s+)?\1\[",
                segment,
            )
            if read_modify:
                found.append(
                    _hit(
                        "D8.shared_state_race",
                        source,
                        node.lineno,
                        f"{where} checks a mapping and writes it without a lock",
                    )
                )
    return found


def _timeouts(files: list[SourceFile]) -> list[Finding]:
    found: list[Finding] = []
    for source in files:
        if _is_test_path(source.path):
            continue
        if source.language == Language.PYTHON:
            found.extend(_python_timeouts(source))
            continue
        lines = source.text.splitlines()
        for index, line in enumerate(lines, start=1):
            if not re.search(r"(?<![\w.])fetch\s*\(|\baxios\.(?:get|post|put|patch|delete)\s*\(", line):
                continue
            window = "\n".join(lines[index - 1 : index + 4])
            if "timeout" in window or "AbortSignal" in window or "signal:" in window:
                continue
            found.append(_hit("D8.missing_timeout", source, index, "Outbound call has no timeout"))
    return found


def _python_timeouts(source: SourceFile) -> list[Finding]:
    try:
        tree = ast.parse(source.text)
    except SyntaxError:
        return []
    found: list[Finding] = []
    verbs = {"get", "post", "put", "patch", "delete", "head", "request", "urlopen"}
    owners = {"requests", "httpx", "urllib.request"}
    if "aiohttp" in source.text or "httpx" in source.text:
        owners.update({"session", "client"})
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        label = _call_name(node.func)
        owner, _, name = label.rpartition(".")
        if name not in verbs or owner not in owners:
            continue
        if any(_keyword_name(item) == "timeout" for item in node.keywords):
            continue
        found.append(_hit("D8.missing_timeout", source, node.lineno, "Outbound call has no timeout"))
    return found


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def _contracts(root: Path, files: list[SourceFile]) -> list[Finding]:
    spec = _spec_paths(root)
    if not spec:
        return []
    routes: set[tuple[str, str]] = set()
    carrier: SourceFile | None = None
    for source in files:
        if _is_test_path(source.path):
            continue
        for method, path in _route_ops(source.text):
            routes.add((method, path))
            carrier = source
    if carrier is None or not routes:
        return []
    found: list[Finding] = []
    for method, path in sorted(routes - spec):
        found.append(_hit("D9.contract_drift", carrier, 1, f"Route {method.upper()} {path} is not in the OpenAPI spec"))
    for method, path in sorted(spec - routes):
        found.append(_hit("D9.contract_drift", carrier, 1, f"OpenAPI {method.upper()} {path} has no route in the tree"))
    return found


def _route_ops(text: str) -> set[tuple[str, str]]:
    found: set[tuple[str, str]] = set()
    for match in _ROUTE.finditer(text):
        method = match.group(1) or match.group(3)
        path = match.group(2) or match.group(4)
        if method and path:
            found.add((method.lower(), path))
    return found


def _spec_paths(root: Path) -> set[tuple[str, str]]:
    for name in ("openapi.json", "openapi.yaml", "openapi.yml"):
        path = root / name
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        if name.endswith(".json"):
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                return set()
            paths = data.get("paths", {}) if isinstance(data, dict) else {}
            return _ops_from_paths(paths)
        found: set[tuple[str, str]] = set()
        inside = False
        current = ""
        for line in text.splitlines():
            if re.match(r"^paths:\s*$", line):
                inside = True
                continue
            if inside and re.match(r"^\S", line):
                inside = False
            if not inside:
                continue
            path_match = re.match(r"^\s{2}(/[^:]+):", line)
            if path_match:
                current = path_match.group(1)
                continue
            method_match = re.match(r"^\s{4}(get|post|put|patch|delete|head|options)\s*:", line, re.I)
            if method_match and current:
                found.add((method_match.group(1).lower(), current))
        return found
    return set()


def _ops_from_paths(paths: object) -> set[tuple[str, str]]:
    found: set[tuple[str, str]] = set()
    if not isinstance(paths, dict):
        return found
    methods = {"get", "post", "put", "patch", "delete", "head", "options"}
    for path, item in paths.items():
        if not isinstance(item, dict):
            continue
        for method in item:
            if str(method).lower() in methods:
                found.add((str(method).lower(), str(path)))
    return found


def _thread_targets(tree: ast.AST) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if _call_name(node.func).rsplit(".", 1)[-1] != "Thread":
            continue
        for item in node.keywords:
            if item.arg == "target" and isinstance(item.value, ast.Name):
                names.add(item.value.id)
    return names


def _migrations(files: list[SourceFile]) -> list[Finding]:
    found: list[Finding] = []
    for source in files:
        parts = set(PurePosixPath(source.path).parts)
        if "migrations" not in parts and "migration" not in source.path:
            continue
        for index, line in enumerate(source.text.splitlines(), start=1):
            if _DROP.search(line) or re.search(r"\bTRUNCATE\b|\bALTER\s+COLUMN\b[^;\n]*\bTYPE\b", line, re.I):
                found.append(_hit("D9.migration_hazard", source, index, "Migration drops, truncates, or retypes a column"))
            if _INDEX.search(line) and not _CONCURRENT.search(line):
                found.append(_hit("D9.migration_hazard", source, index, "Index build is not concurrent"))
    return found


def _env_parity(root: Path, files: list[SourceFile]) -> list[Finding]:
    example = _example_keys(root)
    if example is None:
        return []
    found: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for source in files:
        if _is_test_path(source.path):
            continue
        for index, line in enumerate(source.text.splitlines(), start=1):
            for match in _ENV_USE.finditer(line):
                key = next(group for group in match.groups() if group)
                if key in example or (source.path, key) in seen:
                    continue
                seen.add((source.path, key))
                found.append(_hit("D9.env_parity", source, index, f"{key} is read and missing from .env.example"))
    return found


def _example_keys(root: Path) -> set[str] | None:
    documents: list[Path] = []
    for name in (".env.example", ".env.sample", ".env.template", "docker-compose.yml", "docker-compose.yaml", "compose.yml"):
        path = root / name
        if path.is_file():
            documents.append(path)
    deploy = root / "deploy"
    if deploy.is_dir():
        documents.extend(deploy.glob("*.y*ml"))
    if not documents:
        return None
    keys: set[str] = set()
    for path in documents:
        text = path.read_text(encoding="utf-8")
        for line in text.splitlines():
            match = _ENV_KEY.match(line.strip().lstrip("-").strip())
            if match:
                keys.add(match.group(1))
            named = re.search(r"\bname:\s*([A-Z][A-Z0-9_]+)", line)
            if named:
                keys.add(named.group(1))
    return keys


def _tests(files: list[SourceFile]) -> list[Finding]:
    found: list[Finding] = []
    for source in files:
        if not _is_test_path(source.path):
            continue
        if source.language == Language.PYTHON:
            found.extend(_python_tests(source))
        else:
            found.extend(_script_tests(source))
        found.extend(_flaky(source))
    return found


def _python_tests(source: SourceFile) -> list[Finding]:
    try:
        tree = ast.parse(source.text)
    except SyntaxError:
        return []
    found: list[Finding] = []
    for node in tree.body:
        if not isinstance(node, ast.FunctionDef) or not node.name.startswith("test_"):
            continue
        segment = ast.get_source_segment(source.text, node) or ""
        if _TAUTOLOGY.search(segment) or _same_both_sides(node):
            found.append(_hit("D9.assertion_gap", source, node.lineno, f"{node.name} asserts a constant"))
        elif not any(isinstance(child, ast.Assert) for child in ast.walk(node)) and "pytest.raises" not in segment:
            found.append(_hit("D9.assertion_gap", source, node.lineno, f"{node.name} has no assertion"))
    return found


def _same_both_sides(node: ast.FunctionDef) -> bool:
    for child in ast.walk(node):
        if not isinstance(child, ast.Assert) or not isinstance(child.test, ast.Compare):
            continue
        if len(child.test.ops) == 1 and isinstance(child.test.ops[0], ast.Eq) and ast.dump(child.test.left) == ast.dump(child.test.comparators[0]):
            return True
    return False


def _script_tests(source: SourceFile) -> list[Finding]:
    found: list[Finding] = []
    for match in re.finditer(r"\b(?:it|test)\(\s*['\"][^'\"]+['\"]\s*,\s*(?:async\s*)?\(?\s*\)?\s*=>\s*\{", source.text):
        start = match.end()
        end = source.text.find("\n});", start)
        body = source.text[start : end if end != -1 else start + 400]
        line = source.text[: match.start()].count("\n") + 1
        if _TAUTOLOGY.search(body):
            found.append(_hit("D9.assertion_gap", source, line, "Test asserts a constant"))
        elif "expect(" not in body:
            found.append(_hit("D9.assertion_gap", source, line, "Test has no expect"))
    return found


def _flaky(source: SourceFile) -> list[Finding]:
    if "freezegun" in source.text or "time-machine" in source.text:
        clock = False
    else:
        clock = True
    seeded = "random.seed" in source.text or "seedrandom" in source.text
    found: list[Finding] = []
    for index, line in enumerate(source.text.splitlines(), start=1):
        if clock and re.search(
            r"\b(?:datetime\.now|datetime\.utcnow|time\.time|time\.sleep|Date\.now)\s*\(|\bnew\s+Date\s*\(",
            line,
        ):
            found.append(_hit("D9.flaky_test", source, index, "Test reads the wall clock"))
        if not seeded and re.search(r"\brandom\.(?:random|randint|choice)\s*\(", line):
            found.append(_hit("D9.flaky_test", source, index, "Test draws an unseeded random value"))
        if re.search(r"\brequests\.(?:get|post)\s*\(|\bfetch\s*\(|\burllib\.request\.urlopen\s*\(", line):
            found.append(_hit("D9.flaky_test", source, index, "Test calls the network"))
    return found


def _prompts(files: list[SourceFile]) -> list[Finding]:
    found: list[Finding] = []
    for source in files:
        for index, line in enumerate(source.text.splitlines(), start=1):
            stripped = line.strip()
            comment = stripped.startswith(("#", "//", "--", "/*")) or stripped.startswith("* ")
            prose = PurePosixPath(source.path).suffix.lower() in {".md", ".mdx", ".rst", ".html", ".htm"}
            if (comment or prose) and _PROMPT.search(line):
                found.append(_hit("D9.prompt_leak", source, index, "Pasted model prompt or disclaimer"))
    return found


def _telemetry(files: list[SourceFile]) -> list[Finding]:
    found: list[Finding] = []
    for source in files:
        if source.language != Language.PYTHON or _is_test_path(source.path):
            continue
        try:
            tree = ast.parse(source.text)
        except SyntaxError:
            continue
        for node in tree.body:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if not _route_like(node):
                continue
            segment = ast.get_source_segment(source.text, node) or ""
            if not re.search(r"\.(?:execute|query)\s*\(|\brequests\.|\bfetch\s*\(", segment):
                continue
            if re.search(r"\b(?:log|logger|logging|metric|span|tracer|sentry|correlation_id|trace_id)\b", segment):
                continue
            found.append(_hit("D9.missing_telemetry", source, node.lineno, f"{node.name} mutates data and does not log"))
    return found


def _weak_hash_factory(node: ast.Call) -> bool:
    label = _call_name(node.func)
    if label != "hashlib.new" or not node.args or not isinstance(node.args[0], ast.Constant):
        return False
    value = str(node.args[0].value).lower()
    return value in {"md5", "sha1"}


def _ecb_or_des(node: ast.Call, label: str) -> bool:
    if label in {"Crypto.Cipher.DES.new", "Crypto.Cipher.ARC4.new", "cryptography.hazmat.primitives.ciphers.algorithms.TripleDES"}:
        return True
    for keyword in node.keywords:
        if keyword.arg != "mode":
            continue
        text = ast.unparse(keyword.value) if hasattr(ast, "unparse") else ""
        if text.endswith("MODE_ECB") or text.endswith(".ECB"):
            return True
    return False


def _loop_io(files: list[SourceFile]) -> list[Finding]:
    found: list[Finding] = []
    for source in files:
        if source.language != Language.PYTHON or _is_test_path(source.path):
            continue
        try:
            tree = ast.parse(source.text)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, (ast.For, ast.AsyncFor, ast.While)):
                continue
            for child in ast.walk(node):
                if child is node or not isinstance(child, ast.Call):
                    continue
                called = _call_name(child.func)
                name = called.rsplit(".", 1)[-1]
                owner = called.rsplit(".", 1)[0].rsplit(".")[-1] if "." in called else ""
                query = name in {"execute", "executemany", "scalars", "urlopen"}
                http = name in {"get", "post", "put", "delete", "request"} and owner in {
                    "requests",
                    "httpx",
                    "aiohttp",
                    "client",
                    "session",
                }
                if query or http:
                    found.append(_hit("D9.loop_io", source, node.lineno, "A loop body performs a query or a request"))
                    break
    return found


def _boundary(files: list[SourceFile]) -> list[Finding]:
    found: list[Finding] = []
    raw = ("request.json", "request.get_json", "request.form", "req.body")
    schema = ("BaseModel", "model_validate", "parse_obj", "Schema(", "TypeAdapter", "validator", "zod", "safeParse", "Joi")
    for source in files:
        if _is_test_path(source.path):
            continue
        if source.language in {Language.JAVASCRIPT, Language.TYPESCRIPT, Language.TSX}:
            if any(token in source.text for token in ("req.body", "request.body")) and not any(
                token in source.text for token in ("zod", "safeParse", "Joi")
            ):
                found.append(_hit("D9.boundary_schema", source, 1, "A handler reads a raw body with no schema"))
            continue
        if source.language != Language.PYTHON:
            continue
        try:
            tree = ast.parse(source.text)
        except SyntaxError:
            continue
        for node in tree.body:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) or not _route_like(node):
                continue
            segment = ast.get_source_segment(source.text, node) or ""
            if any(token in segment for token in raw) and not any(token in segment for token in schema):
                found.append(_hit("D9.boundary_schema", source, node.lineno, f"{node.name} reads a raw body with no schema"))
    return found


def _graphql(root: Path, files: list[SourceFile]) -> list[Finding]:
    schema_path = root / "schema.graphql"
    if not schema_path.is_file():
        return []
    fields = _graphql_fields(schema_path.read_text(encoding="utf-8"))
    if not fields:
        return []
    resolvers: set[str] = set()
    carrier = files[0] if files else None
    for source in files:
        if _is_test_path(source.path):
            continue
        carrier = source
        for match in re.finditer(r"\bdef\s+resolve_(\w+)\s*\(", source.text):
            resolvers.add(match.group(1))
    if not resolvers:
        return []
    found: list[Finding] = []
    target = carrier or files[0]
    for name in sorted(fields - resolvers):
        found.append(_hit("D9.graphql_drift", target, 1, f"GraphQL field {name} has no resolve_{name}"))
    return found


def _graphql_fields(text: str) -> set[str]:
    fields: set[str] = set()
    current = ""
    for line in text.splitlines():
        header = re.match(r"^type\s+(Query|Mutation)\b", line)
        if header:
            current = header.group(1)
            continue
        if current and re.match(r"^\S", line):
            current = ""
        if current:
            field = re.match(r"^\s+(\w+)\s*(?:\(|:)", line)
            if field and field.group(1) not in {"type"}:
                fields.add(field.group(1))
    return fields


def _registry(root: Path) -> list[Finding]:
    if os.environ.get("VIBECLEANER_ONLINE_CHECKS", "").strip() != "1":
        return []
    declared = _python_declared(root) | _node_declared(root)
    found: list[Finding] = []
    for name in sorted(declared):
        if name in _POPULAR or len(name) < 4:
            continue
        if _distance_to_popular(name) == 1:
            continue
        status = _registry_status(name)
        if status != 404:
            continue
        found.append(
            Finding(
                rule_id="D9.registry_missing",
                file="pyproject.toml" if (root / "pyproject.toml").is_file() else "package.json",
                line=1,
                message=f"Dependency {name} is not on the public registry",
                symbol=name,
            )
        )
    return found


def _distance_to_popular(name: str) -> int:
    best = 3
    for popular in _POPULAR:
        best = min(best, _distance(name, popular))
        if best == 0:
            return 0
    return best


def _registry_status(name: str) -> int | None:
    """Return the HTTP status from PyPI, or None when the network is unavailable."""
    import urllib.error
    import urllib.request

    url = f"https://pypi.org/pypi/{name}/json"
    try:
        with urllib.request.urlopen(url, timeout=1.5) as response:
            return getattr(response, "status", 200)
    except urllib.error.HTTPError as exc:
        return exc.code
    except (urllib.error.URLError, TimeoutError, OSError):
        return None


def advisories_in(payload: object) -> list[str]:
    """Ids from an OSV query body. An empty list means that version is clean."""
    if not isinstance(payload, dict):
        return []
    vulns = payload.get("vulns")
    if not isinstance(vulns, list):
        return []
    return [str(item.get("id")) for item in vulns if isinstance(item, dict) and item.get("id")]


def _advisories(root: Path) -> list[Finding]:
    if os.environ.get("VIBECLEANER_ONLINE_CHECKS", "").strip() != "1":
        return []
    specs = _pinned_python(root)
    found: list[Finding] = []
    for name, version in specs:
        payload = _osv_query(name, version)
        ids = advisories_in(payload)
        if not ids:
            continue
        found.append(
            Finding(
                rule_id="D9.registry_missing",
                file="pyproject.toml",
                line=1,
                message=f"{name}=={version} is named by {', '.join(ids[:3])}",
                symbol=name,
            )
        )
    return found


def _pinned_python(root: Path) -> list[tuple[str, str]]:
    pinned: list[tuple[str, str]] = []
    path = root / "pyproject.toml"
    if path.is_file():
        text = path.read_text(encoding="utf-8")
        for match in re.findall(r"""['"]([^'"]+)['"]""", text):
            parts = re.match(r"^([A-Za-z0-9_.-]+)==([A-Za-z0-9*._+-]+)$", match)
            if parts:
                pinned.append((parts.group(1), parts.group(2)))
    requirements = root / "requirements.txt"
    if requirements.is_file():
        for line in requirements.read_text(encoding="utf-8").splitlines():
            parts = re.match(r"^([A-Za-z0-9_.-]+)==([A-Za-z0-9*._+-]+)\s*(?:#.*)?$", line.strip())
            if parts:
                pinned.append((parts.group(1), parts.group(2)))
    return pinned


def _osv_query(name: str, version: str) -> dict | None:
    import json as _json
    import urllib.error
    import urllib.request

    body = _json.dumps({"version": version, "package": {"name": name, "ecosystem": "PyPI"}}).encode()
    request = urllib.request.Request(
        "https://api.osv.dev/v1/query",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=1.5) as response:
            parsed = _json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return None
    return parsed if isinstance(parsed, dict) else None


def _route_like(node: ast.AST) -> bool:
    name = getattr(node, "name", "")
    if name.startswith(("get_", "post_", "put_", "patch_", "delete_")):
        return True
    for decorator in getattr(node, "decorator_list", []):
        text = ast.unparse(decorator) if hasattr(ast, "unparse") else ""
        if re.search(r"\.(?:get|post|put|patch|delete|route)\b", text):
            return True
    return False
