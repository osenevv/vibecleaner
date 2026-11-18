"""Shared tree-sitter parsers and node helpers."""

from __future__ import annotations

import threading
from typing import Iterator

import tree_sitter_python
import tree_sitter_typescript
from tree_sitter import Language, Node, Parser

from vibecleaner.models import Language as SourceLanguage
from vibecleaner.models import SourceFile

_PY_LANGUAGE = Language(tree_sitter_python.language())
_TS_LANGUAGE = Language(tree_sitter_typescript.language_typescript())
_TSX_LANGUAGE = Language(tree_sitter_typescript.language_tsx())
_THREAD_PARSERS = threading.local()


def parser_for(source: SourceFile) -> Parser | None:
    if source.language == SourceLanguage.PYTHON:
        key, language = "python", _PY_LANGUAGE
    elif source.language == SourceLanguage.TSX or source.path.endswith(".jsx"):
        key, language = "tsx", _TSX_LANGUAGE
    elif source.language in {SourceLanguage.TYPESCRIPT, SourceLanguage.JAVASCRIPT}:
        key, language = "typescript", _TS_LANGUAGE
    else:
        return None
    cache: dict[str, Parser] | None = getattr(_THREAD_PARSERS, "parsers", None)
    if cache is None:
        cache = {}
        _THREAD_PARSERS.parsers = cache
    parser = cache.get(key)
    if parser is None:
        parser = Parser(language)
        cache[key] = parser
    return parser


def parse_root(source: SourceFile) -> Node | None:
    parser = parser_for(source)
    if parser is None:
        return None
    return parser.parse(source.text.encode("utf-8")).root_node


def node_text(node: Node) -> str:
    raw = node.text
    if isinstance(raw, bytes):
        return raw.decode("utf-8", errors="replace")
    return str(raw)


def python_string(node: Node) -> str | None:
    if node.type != "string" or any(child.type == "interpolation" for child in node.children):
        return None
    return "".join(node_text(child) for child in node.children if child.type == "string_content")


def script_string(node: Node) -> str | None:
    if node.type == "string":
        if any(child.is_named and child.type != "string_fragment" for child in node.children):
            return None
        return "".join(node_text(child) for child in node.children if child.type == "string_fragment")
    if node.type == "template_string":
        if any(child.type == "template_substitution" for child in node.children):
            return None
        return "".join(node_text(child) for child in node.children if child.type == "string_fragment")
    return None


def walk_tree(node: Node) -> Iterator[Node]:
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(reversed(current.named_children))


def line_text(text: str, line: int) -> str:
    rows = text.splitlines()
    if 1 <= line <= len(rows):
        return rows[line - 1].strip()
    return ""


def attr_leaf(node: Node) -> str:
    if node.type in {"identifier", "property_identifier"}:
        return node_text(node)
    if node.type == "attribute":
        attr = node.child_by_field_name("attribute")
        return node_text(attr) if attr is not None else ""
    if node.type == "member_expression":
        prop = node.child_by_field_name("property")
        return node_text(prop) if prop is not None else ""
    if node.type in {"call", "call_expression"}:
        func = node.child_by_field_name("function")
        return attr_leaf(func) if func is not None else ""
    return ""


def decorator_leaf(decorator: Node) -> str:
    inner = decorator.named_children[0] if decorator.named_children else None
    if inner is None:
        return ""
    if inner.type in {"call", "call_expression"}:
        func = inner.child_by_field_name("function")
        return attr_leaf(func) if func is not None else ""
    return attr_leaf(inner)


def callee_name(node: Node) -> str:
    if node.type in {"identifier", "property_identifier"}:
        return node_text(node)
    if node.type == "attribute":
        obj = node.child_by_field_name("object")
        attr = node.child_by_field_name("attribute")
        if obj is None or attr is None:
            return ""
        prefix = callee_name(obj)
        leaf = node_text(attr)
        return f"{prefix}.{leaf}" if prefix else leaf
    if node.type == "member_expression":
        obj = node.child_by_field_name("object")
        prop = node.child_by_field_name("property")
        if obj is None or prop is None:
            return ""
        prefix = callee_name(obj)
        leaf = node_text(prop)
        return f"{prefix}.{leaf}" if prefix else leaf
    if node.type in {"call", "call_expression"}:
        func = node.child_by_field_name("function")
        return callee_name(func) if func is not None else ""
    return ""
