"""Code-only text for usage checks. Comments and string contents are blanked."""

from __future__ import annotations

import re
from pathlib import PurePosixPath

from tree_sitter import Node

from vibecleaner.models import Language, SourceFile
from vibecleaner.preflight.patterns import _SQL_KEYWORD
from vibecleaner.ts_parse import node_text, parse_root, walk_tree

_PROSE_SUFFIXES = frozenset({".md", ".mdx", ".rst", ".txt"})
_PROSE_NAMES = frozenset({"license", "licence", "copying"})
_CONFIG_SUFFIXES = frozenset({".json", ".yaml", ".yml", ".toml"})
_MARKUP_SUFFIXES = frozenset({".html", ".htm", ".vue", ".jinja", ".j2"})
_BLANK_LANGUAGES = frozenset(
    {
        Language.PYTHON,
        Language.TYPESCRIPT,
        Language.TSX,
        Language.JAVASCRIPT,
    }
)
_BLANK_SUFFIXES = frozenset(
    {".py", ".pyi", ".pyw", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts"}
)
_BLANK_NODE_TYPES = frozenset({"comment", "string_content", "string_fragment", "regex_pattern"})
_PY_SUFFIXES = frozenset({".py", ".pyi", ".pyw"})
_RE_METHODS = frozenset({"compile", "search", "match", "fullmatch", "finditer", "sub", "split"})
_PLUS_TYPES = frozenset({"binary_operator", "binary_expression"})
_REQUEST_EXPR = re.compile(
    r"(?i)\b(?:request|req|body|params|query|form|payload|args|user_input|search)\b"
)
_SQL_STATEMENT = re.compile(
    r"(?i)\b(?:SELECT\b[^;\n]{0,500}\bFROM\b|"
    r"INSERT\s+INTO\s+|"
    r"UPDATE\s+['\"`]?[A-Za-z_][\w.]*['\"`]?\s+SET\b|"
    r"DELETE\s+FROM\s+)"
)


def is_prose_path(path: str) -> bool:
    pure = PurePosixPath(path)
    if pure.suffix.lower() in _PROSE_SUFFIXES:
        return True
    return pure.name.lower() in _PROSE_NAMES or pure.stem.lower() in _PROSE_NAMES


def is_data_config_path(path: str) -> bool:
    pure = PurePosixPath(path)
    name = pure.name.lower()
    if name == ".env" or name.startswith(".env."):
        return True
    return pure.suffix.lower() in _CONFIG_SUFFIXES


def is_markup_path(path: str) -> bool:
    return PurePosixPath(path).suffix.lower() in _MARKUP_SUFFIXES


def is_sql_path(path: str) -> bool:
    return PurePosixPath(path).suffix.lower() == ".sql"


def is_blankable(source: SourceFile) -> bool:
    if source.language in _BLANK_LANGUAGES:
        return True
    return PurePosixPath(source.path).suffix.lower() in _BLANK_SUFFIXES


def code_only_text(source: SourceFile) -> str:
    """Return ``source`` with comments and string or regex contents replaced by spaces."""
    if not is_blankable(source):
        return source.text
    root = parse_root(source)
    if root is None:
        return source.text
    raw = bytearray(source.text.encode("utf-8"))
    for node in walk_tree(root):
        if node.type not in _BLANK_NODE_TYPES:
            continue
        if node.type == "string_fragment" and _is_module_specifier_fragment(node):
            continue
        _blank_span(raw, node.start_byte, node.end_byte)
    return raw.decode("utf-8")


def comments_blanked(source: SourceFile) -> str:
    """Return ``source`` with comments, docstrings, and regex literals replaced by spaces."""
    if is_sql_path(source.path):
        return _blank_sql_comments(source.text)
    if not is_blankable(source):
        return source.text
    root = parse_root(source)
    if root is None:
        return source.text
    raw = bytearray(source.text.encode("utf-8"))
    is_python = _is_python_source(source)
    for node in walk_tree(root):
        if node.type in {"comment", "regex_pattern"}:
            _blank_span(raw, node.start_byte, node.end_byte)
            continue
        if is_python and node.type == "string" and node.parent is not None and node.parent.type == "expression_statement":
            _blank_span(raw, node.start_byte, node.end_byte)
            continue
        if _is_regex_call(node):
            args = node.child_by_field_name("arguments")
            if args is not None:
                for child in walk_tree(args):
                    if child.type in {"string_content", "string_fragment"}:
                        _blank_span(raw, child.start_byte, child.end_byte)
    return raw.decode("utf-8")


def _is_python_source(source: SourceFile) -> bool:
    if source.language == Language.PYTHON:
        return True
    return PurePosixPath(source.path).suffix.lower() in _PY_SUFFIXES


def _is_module_specifier_fragment(node: Node) -> bool:
    parent = node.parent
    if parent is None or parent.type != "string":
        return False
    grand = parent.parent
    if grand is None:
        return False
    if grand.type in {"import_statement", "export_statement"}:
        return grand.child_by_field_name("source") == parent
    if grand.type != "arguments":
        return False
    call = grand.parent
    if call is None or call.type != "call_expression":
        return False
    if call.child_by_field_name("arguments") != grand:
        return False
    args = grand.named_children
    if not args or args[0] != parent:
        return False
    func = call.child_by_field_name("function")
    if func is None:
        return False
    if func.type == "import":
        return True
    return func.type == "identifier" and node_text(func) in {"require", "import"}


def _is_regex_call(node: Node) -> bool:
    if node.type in {"call", "call_expression"}:
        target = node.child_by_field_name("function")
    elif node.type == "new_expression":
        target = node.child_by_field_name("constructor")
    else:
        return False
    if target is None:
        return False
    if target.type == "identifier":
        return node_text(target) == "RegExp"
    if target.type == "attribute":
        obj = target.child_by_field_name("object")
        attr = target.child_by_field_name("attribute")
        return (
            obj is not None
            and attr is not None
            and obj.type == "identifier"
            and node_text(obj) == "re"
            and node_text(attr) in _RE_METHODS
        )
    if target.type == "member_expression":
        prop = target.child_by_field_name("property")
        return prop is not None and node_text(prop) == "RegExp"
    return False


def _blank_sql_comments(text: str) -> str:
    chars = list(text)
    index = 0
    length = len(chars)
    while index < length:
        ch = chars[index]
        if ch in {"'", '"'}:
            index = _skip_sql_quote(chars, index)
            continue
        if ch == "-" and index + 1 < length and chars[index + 1] == "-":
            while index < length and chars[index] not in "\n\r":
                chars[index] = " "
                index += 1
            continue
        if ch == "/" and index + 1 < length and chars[index + 1] == "*":
            chars[index] = " "
            chars[index + 1] = " "
            index += 2
            while index < length and not (
                chars[index] == "*" and index + 1 < length and chars[index + 1] == "/"
            ):
                if chars[index] not in "\n\r":
                    chars[index] = " "
                index += 1
            if index < length:
                chars[index] = " "
                index += 1
            if index < length and chars[index] == "/":
                chars[index] = " "
                index += 1
            continue
        index += 1
    return "".join(chars)


def _skip_sql_quote(chars: list[str], index: int) -> int:
    quote = chars[index]
    index += 1
    length = len(chars)
    while index < length:
        if chars[index] == quote:
            if index + 1 < length and chars[index + 1] == quote:
                index += 2
                continue
            return index + 1
        index += 1
    return index


def sql_statements(source: SourceFile) -> list[tuple[int, str]]:
    """SQL statement literals in a parsed code file, as ``(line, text)``."""
    root = parse_root(source)
    if root is None:
        return []
    found: list[tuple[int, str]] = []
    for node in walk_tree(root):
        if node.type not in {"string", "template_string"}:
            continue
        text = _literal_contents(node)
        if text and _SQL_STATEMENT.search(text):
            found.append((node.start_point[0] + 1, text))
    return found


def request_sql_lines(source: SourceFile) -> list[int]:
    """Lines where an f-string or concatenation builds SQL from request data."""
    root = parse_root(source)
    if root is None:
        return []
    lines: list[int] = []
    seen: set[int] = set()
    for node in walk_tree(root):
        line = _request_sql_line(node)
        if line is None or line in seen:
            continue
        seen.add(line)
        lines.append(line)
    return lines


def _blank_span(buf: bytearray, start: int, end: int) -> None:
    start = max(0, start)
    end = min(len(buf), end)
    for index in range(start, end):
        if buf[index] not in (0x0A, 0x0D):
            buf[index] = 0x20


def _literal_contents(node: Node) -> str:
    if node.type == "string":
        return "".join(node_text(child) for child in node.children if child.type == "string_content")
    if node.type == "template_string":
        return "".join(node_text(child) for child in node.children if child.type == "string_fragment")
    return ""


def _request_sql_line(node: Node) -> int | None:
    if _interpolated_sql(node):
        return node.start_point[0] + 1
    if node.type in _PLUS_TYPES and _is_plus(node) and not _nested_plus(node) and _concat_sql(node):
        return node.start_point[0] + 1
    return None


def _interpolated_sql(node: Node) -> bool:
    if node.type == "string":
        holes = [child for child in node.children if child.type == "interpolation"]
    elif node.type == "template_string":
        holes = [child for child in node.children if child.type == "template_substitution"]
    else:
        return False
    if not holes or not _SQL_KEYWORD.search(_literal_contents(node)):
        return False
    return any(_REQUEST_EXPR.search(node_text(hole)) for hole in holes)


def _concat_sql(node: Node) -> bool:
    parts = _plus_operands(node)
    if parts is None:
        return False
    sql = False
    request = False
    for part in parts:
        if part.type in {"string", "template_string"}:
            literal = _literal_contents(part)
            if literal and _SQL_KEYWORD.search(literal):
                sql = True
            if _substitution_requests(part):
                request = True
            continue
        if _REQUEST_EXPR.search(node_text(part)):
            request = True
    return sql and request


def _substitution_requests(node: Node) -> bool:
    kind = "interpolation" if node.type == "string" else "template_substitution"
    if node.type not in {"string", "template_string"}:
        return False
    return any(child.type == kind and _REQUEST_EXPR.search(node_text(child)) for child in node.children)


def _plus_operands(node: Node) -> list[Node] | None:
    if node.type not in _PLUS_TYPES or not _is_plus(node):
        return None
    left = node.child_by_field_name("left")
    right = node.child_by_field_name("right")
    if left is None or right is None:
        return None
    parts: list[Node] = []
    for side in (left, right):
        nested = _plus_operands(side)
        if nested is None:
            parts.append(side)
        else:
            parts.extend(nested)
    return parts


def _is_plus(node: Node) -> bool:
    return any(not child.is_named and node_text(child) == "+" for child in node.children)


def _nested_plus(node: Node) -> bool:
    parent = node.parent
    return parent is not None and parent.type in _PLUS_TYPES and _is_plus(parent)
