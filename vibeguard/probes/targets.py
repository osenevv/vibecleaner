"""Functions that overlap a diff, ranked so pure code is probed first."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import PurePosixPath

from tree_sitter import Node

from vibeguard.probes.spans import (
    ChangedLines,
    as_source_file,
    is_skipped_path,
    language_of,
    normalize_changed,
    overlaps,
    read_text,
)
from vibeguard.ts_parse import attr_leaf, node_text, parse_root

_ROUTE_LEAVES = frozenset(
    {"get", "post", "put", "patch", "delete", "head", "options", "route", "api_route", "tool"}
)
_HTTP_NAMES = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"})
_IO_OWNERS = frozenset({"requests", "httpx", "subprocess", "socket", "urllib", "aiohttp", "axios"})
_TS_IO = ("fetch(", "axios.", "fs.", "child_process", "http.request", "https.")


@dataclass(frozen=True)
class Target:
    path: str
    language: str
    qualname: str
    name: str
    module: str
    start_line: int
    end_line: int
    signature: str
    docstring: str | None
    parameters: tuple[tuple[str, str, str], ...]
    returns: str
    pure: bool
    route: bool
    io: bool
    is_async: bool
    method: bool
    variadic: bool

    def signature_key(self) -> tuple[object, ...]:
        return (self.name, self.parameters, self.returns, self.is_async, self.variadic)


def select_targets(cwd: Path, changed: ChangedLines) -> list[Target]:
    found: list[Target] = []
    for rel, lines in sorted(normalize_changed(cwd, changed).items()):
        if is_skipped_path(rel) or language_of(rel) is None:
            continue
        text = read_text(cwd, rel)
        if text is None:
            continue
        for target in extract_targets(rel, text):
            if target.route or target.name.startswith("test_"):
                continue
            if not overlaps(target.start_line, target.end_line, lines):
                continue
            found.append(target)
    found.sort(key=lambda item: (not item.pure, item.path, item.start_line, item.qualname))
    return found


def extract_targets(rel: str, source: str) -> list[Target]:
    if rel.endswith(".py"):
        return _python_targets(rel, source)
    if language_of(rel) is None:
        return []
    return _script_targets(rel, source)


def _python_targets(rel: str, source: str) -> list[Target]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    module = _module_name(rel)
    found: list[Target] = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            found.append(_python_target(rel, module, node, None))
        elif isinstance(node, ast.ClassDef):
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    found.append(_python_target(rel, module, item, node.name))
    return found


def _python_target(
    rel: str,
    module: str,
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    class_name: str | None,
) -> Target:
    start, end = _python_span(node)
    route = any(_decorator_leaf(item) in _ROUTE_LEAVES for item in node.decorator_list)
    io = _python_io(node)
    parameters = _parameters(node)
    returns = ast.unparse(node.returns) if node.returns is not None else ""
    qualname = f"{class_name}.{node.name}" if class_name else node.name
    prefix = "async def" if isinstance(node, ast.AsyncFunctionDef) else "def"
    rendered = f"{prefix} {node.name}({ast.unparse(node.args)})"
    if returns:
        rendered = f"{rendered} -> {returns}"
    return Target(
        path=rel,
        language="python",
        qualname=qualname,
        name=node.name,
        module=module,
        start_line=start,
        end_line=end,
        signature=rendered,
        docstring=_cap_doc(ast.get_docstring(node)),
        parameters=parameters,
        returns=returns,
        pure=not io and not route,
        route=route,
        io=io,
        is_async=isinstance(node, ast.AsyncFunctionDef),
        method=class_name is not None,
        variadic=node.args.vararg is not None or node.args.kwarg is not None,
    )


def _script_targets(rel: str, source: str) -> list[Target]:
    parsed = as_source_file(rel, source)
    if parsed is None:
        return []
    root = parse_root(parsed)
    if root is None:
        return []
    module = _module_name(rel)
    found: list[Target] = []
    for child in root.named_children:
        _script_visit(rel, module, source, child, None, found)
    return found


def _script_visit(
    rel: str,
    module: str,
    source: str,
    node: Node,
    class_name: str | None,
    found: list[Target],
) -> None:
    if node.type == "export_statement":
        for child in node.named_children:
            _script_visit(rel, module, source, child, class_name, found)
        return
    if node.type == "function_declaration":
        target = _script_target(rel, module, source, node, class_name)
        if target is not None:
            found.append(target)
        return
    if node.type == "class_declaration":
        name_node = node.child_by_field_name("name")
        body = node.child_by_field_name("body")
        if name_node is None or body is None:
            return
        for child in body.named_children:
            if child.type == "method_definition":
                target = _script_target(rel, module, source, child, node_text(name_node))
                if target is not None:
                    found.append(target)
        return
    if node.type in {"lexical_declaration", "variable_declaration"}:
        for declarator in node.named_children:
            if declarator.type != "variable_declarator":
                continue
            name_node = declarator.child_by_field_name("name")
            value = declarator.child_by_field_name("value")
            if name_node is None or value is None:
                continue
            if value.type not in {"arrow_function", "function_expression"}:
                continue
            target = _script_target(rel, module, source, value, class_name, node_text(name_node))
            if target is not None:
                found.append(target)


def _script_target(
    rel: str,
    module: str,
    source: str,
    node: Node,
    class_name: str | None,
    explicit_name: str | None = None,
) -> Target | None:
    name_node = node.child_by_field_name("name")
    name = explicit_name or (node_text(name_node) if name_node is not None else "")
    if not name:
        return None
    body = node.child_by_field_name("body")
    if body is None:
        return None
    raw = source.encode("utf-8")
    signature = raw[node.start_byte : body.start_byte].decode("utf-8", errors="replace").strip()
    body_text = node_text(body)
    io = any(marker in body_text for marker in _TS_IO)
    route = _script_route(rel, name, node)
    start = node.start_point[0] + 1
    end = node.end_point[0] + 1
    if node.end_point[1] == 0 and end > start:
        end -= 1
    qualname = f"{class_name}.{name}" if class_name else name
    return Target(
        path=rel,
        language="typescript",
        qualname=qualname,
        name=name,
        module=module,
        start_line=start,
        end_line=max(start, end),
        signature=signature,
        docstring=_script_doc(node),
        parameters=(),
        returns="",
        pure=not io and not route,
        route=route,
        io=io,
        is_async=any(child.type == "async" for child in node.children),
        method=class_name is not None,
        variadic=False,
    )


def _script_route(rel: str, name: str, node: Node) -> bool:
    if name in _HTTP_NAMES or name.upper() in _HTTP_NAMES:
        return True
    if _route_file(rel) and name.upper() in _HTTP_NAMES:
        return True
    return _express_handler(node)


def _express_handler(node: Node) -> bool:
    current = node.parent
    while current is not None:
        if current.type == "call_expression":
            func = current.child_by_field_name("function")
            args = current.child_by_field_name("arguments")
            if func is not None and args is not None and _contains(args, node):
                return attr_leaf(func).lower() in _ROUTE_LEAVES
            return False
        if current.type in {"function_declaration", "class_declaration", "program", "export_statement"}:
            return False
        current = current.parent
    return False


def _script_doc(node: Node) -> str | None:
    current = node
    for _ in range(3):
        prev = current.prev_sibling
        if prev is not None and prev.type == "comment":
            return _cap_doc(node_text(prev).strip())
        parent = current.parent
        if parent is None or parent.type != "export_statement":
            return None
        current = parent
    return None


def _parameters(node: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[tuple[str, str, str], ...]:
    args = node.args
    groups = (
        ("posonly", args.posonlyargs),
        ("pos", args.args),
        ("kwonly", args.kwonlyargs),
    )
    found: list[tuple[str, str, str]] = []
    for kind, items in groups:
        for arg in items:
            if arg.arg in {"self", "cls"}:
                continue
            annotation = ast.unparse(arg.annotation) if arg.annotation is not None else ""
            found.append((kind, arg.arg, annotation))
    return tuple(found)


def _python_io(node: ast.AST) -> bool:
    for child in ast.walk(node):
        if isinstance(child, ast.Call) and _call_is_io(child):
            return True
    return False


def _call_is_io(node: ast.Call) -> bool:
    parts = _call_parts(node.func)
    if not parts:
        return False
    if parts[0] in _IO_OWNERS:
        return True
    if parts[-1] == "open" and (len(parts) == 1 or parts[0] in {"io", "pathlib", "Path"}):
        return True
    if parts[0] == "os" and parts[-1] in {"system", "popen", "remove", "unlink"}:
        return True
    return len(parts) > 1 and parts[-1] in {"read_text", "write_text", "read_bytes", "write_bytes"}


def _call_parts(expr: ast.expr) -> tuple[str, ...]:
    parts: list[str] = []
    current: ast.expr | None = expr
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    parts.reverse()
    return tuple(parts)


def _decorator_leaf(expr: ast.expr) -> str:
    if isinstance(expr, ast.Call):
        return _decorator_leaf(expr.func)
    if isinstance(expr, ast.Attribute):
        return expr.attr
    if isinstance(expr, ast.Name):
        return expr.id
    return ""


def _python_span(node: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[int, int]:
    start = node.lineno
    for decorator in node.decorator_list:
        deco_line = getattr(decorator, "lineno", start)
        if isinstance(deco_line, int):
            start = min(start, deco_line)
    end = node.end_lineno or node.lineno
    return start, end


def _module_name(rel: str) -> str:
    pure = PurePosixPath(rel)
    parts = pure.parent.parts if pure.name == "__init__.py" else pure.with_suffix("").parts
    return ".".join(part for part in parts if part not in {"", "."})


def _cap_doc(text: str | None) -> str | None:
    if not text:
        return None
    if len(text) > 2000:
        return text[:2000]
    return text


def _contains(parent: Node, child: Node) -> bool:
    return parent.start_byte <= child.start_byte and child.end_byte <= parent.end_byte


def _route_file(rel: str) -> bool:
    parts = PurePosixPath(rel).parts
    name = parts[-1] if parts else ""
    if name.startswith("route.") and "app" in parts:
        return True
    return "pages" in parts and "api" in parts
