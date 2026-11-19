"""Small source mutators. Python uses ast; TypeScript uses tree-sitter spans."""

from __future__ import annotations

import ast
import copy
import re
from collections import defaultdict
from dataclasses import dataclass

from tree_sitter import Node

from vibecleaner.probes.spans import as_source_file, language_of
from vibecleaner.ts_parse import node_text, parse_root, walk_tree

OPERATORS = (
    "cmp_flip",
    "bool_flip",
    "negate_if",
    "off_by_one",
    "return_none",
    "drop_guard",
    "remove_await",
)

_CMP_FLIP: dict[type[ast.cmpop], type[ast.cmpop]] = {
    ast.Eq: ast.NotEq,
    ast.NotEq: ast.Eq,
    ast.Lt: ast.GtE,
    ast.GtE: ast.Lt,
    ast.Gt: ast.LtE,
    ast.LtE: ast.Gt,
    ast.Is: ast.IsNot,
    ast.IsNot: ast.Is,
    ast.In: ast.NotIn,
    ast.NotIn: ast.In,
}
_TS_CMP = {
    "===": "!==",
    "!==": "===",
    "==": "!=",
    "!=": "==",
    "<": ">=",
    ">": "<=",
    "<=": ">",
    ">=": "<",
}
_NEEDS_BODY = (
    ast.FunctionDef,
    ast.AsyncFunctionDef,
    ast.ClassDef,
    ast.For,
    ast.AsyncFor,
    ast.While,
    ast.With,
    ast.AsyncWith,
    ast.If,
    ast.Try,
    ast.ExceptHandler,
)
_TYPE_ANCESTORS = frozenset(
    {"type_annotation", "type_arguments", "type_parameter", "type_alias_declaration"}
)


@dataclass(frozen=True)
class Mutant:
    operator: str
    path: str
    line: int
    source: str


_TOKEN_FLIPS = (
    (re.compile(r"(?<![=!])==(?!=)"), "!="),
    (re.compile(r"(?<![=!])!=(?!=)"), "=="),
    (re.compile(r"(?<![<>=])<(?!=)"), ">"),
    (re.compile(r"(?<![<>=])>(?!=)"), "<"),
    (re.compile(r"\btrue\b"), "false"),
    (re.compile(r"\bfalse\b"), "true"),
    (re.compile(r"\bTrue\b"), "False"),
    (re.compile(r"\bFalse\b"), "True"),
)
_TOKEN_INT = re.compile(r"(?<![\w.])(\d+)(?![\w.])")


def file_candidates(path: str, source: str, lines: frozenset[int]) -> list[Mutant]:
    if path.endswith(".py"):
        return _python_candidates(path, source, lines)
    if language_of(path) is None:
        return _token_candidates(path, source, lines)
    return _script_candidates(path, source, lines)


def _token_candidates(path: str, source: str, lines: frozenset[int]) -> list[Mutant]:
    """Comparison, boolean, and integer edits for a language without a grammar."""
    found: list[Mutant] = []
    rows = source.splitlines(keepends=True)
    for number, row in enumerate(rows, start=1):
        if number not in lines:
            continue
        for pattern, replacement in _TOKEN_FLIPS:
            match = pattern.search(row)
            if match is None:
                continue
            edited = row[: match.start()] + replacement + row[match.end() :]
            found.append(Mutant("cmp_flip" if replacement in {"==", "!=", "<", ">"} else "bool_flip", path, number, _join(rows, number, edited)))
        match = _TOKEN_INT.search(row)
        if match is not None:
            edited = row[: match.start(1)] + str(int(match.group(1)) + 1) + row[match.end(1) :]
            found.append(Mutant("off_by_one", path, number, _join(rows, number, edited)))
    return found


def _join(rows: list[str], number: int, edited: str) -> str:
    copied = list(rows)
    copied[number - 1] = edited
    return "".join(copied)


def select_mutants(candidates: list[Mutant], limit: int) -> list[Mutant]:
    groups: dict[str, list[Mutant]] = defaultdict(list)
    for mutant in candidates:
        groups[mutant.operator].append(mutant)
    order = [op for op in OPERATORS if op in groups]
    order.extend(op for op in groups if op not in order)
    selected: list[Mutant] = []
    seen: set[tuple[str, str]] = set()
    while len(selected) < limit and any(groups.values()):
        progressed = False
        for op in order:
            pool = groups[op]
            if not pool:
                continue
            mutant = pool.pop(0)
            progressed = True
            key = (mutant.path, mutant.source)
            if key in seen:
                continue
            seen.add(key)
            selected.append(mutant)
            if len(selected) >= limit:
                break
        if not progressed:
            break
    return selected


def _python_candidates(path: str, source: str, lines: frozenset[int]) -> list[Mutant]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    parents = _parents(tree)
    raw = source.encode("utf-8")
    starts = _line_starts(raw)
    found: list[Mutant] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Compare):
            _flip_compares(found, path, source, raw, starts, lines, node)
        elif isinstance(node, ast.BoolOp) and isinstance(node.op, (ast.And, ast.Or)):
            _flip_bool(found, path, source, raw, starts, lines, node)
        elif isinstance(node, ast.If):
            _negate_if(found, path, source, raw, starts, lines, node)
            _drop_guard(found, path, source, raw, starts, lines, parents, node)
        elif isinstance(node, ast.Return):
            _return_none(found, path, source, raw, starts, lines, node)
        elif isinstance(node, ast.Constant):
            _off_by_one(found, path, source, raw, starts, lines, parents, node)
    return found


def _flip_compares(
    found: list[Mutant],
    path: str,
    source: str,
    raw: bytes,
    starts: list[int],
    lines: frozenset[int],
    node: ast.Compare,
) -> None:
    if not _touches(node, lines):
        return
    span = _span_bytes(raw, starts, node)
    if span is None:
        return
    for index, op in enumerate(node.ops):
        replacement = _CMP_FLIP.get(type(op))
        if replacement is None:
            continue
        clone = copy.deepcopy(node)
        clone.ops[index] = replacement()
        _emit(found, path, source, raw, span[0], span[1], ast.unparse(clone), "cmp_flip", node.lineno)


def _flip_bool(
    found: list[Mutant],
    path: str,
    source: str,
    raw: bytes,
    starts: list[int],
    lines: frozenset[int],
    node: ast.BoolOp,
) -> None:
    if not _touches(node, lines):
        return
    span = _span_bytes(raw, starts, node)
    if span is None:
        return
    clone = copy.deepcopy(node)
    clone.op = ast.Or() if isinstance(node.op, ast.And) else ast.And()
    _emit(found, path, source, raw, span[0], span[1], ast.unparse(clone), "bool_flip", node.lineno)


def _negate_if(
    found: list[Mutant],
    path: str,
    source: str,
    raw: bytes,
    starts: list[int],
    lines: frozenset[int],
    node: ast.If,
) -> None:
    if node.lineno not in lines:
        return
    span = _span_bytes(raw, starts, node.test)
    if span is None:
        return
    if isinstance(node.test, ast.UnaryOp) and isinstance(node.test.op, ast.Not):
        inner = _span_bytes(raw, starts, node.test.operand)
        if inner is None:
            return
        new = raw[inner[0] : inner[1]].decode("utf-8")
    else:
        new = "not (" + raw[span[0] : span[1]].decode("utf-8") + ")"
    _emit(found, path, source, raw, span[0], span[1], new, "negate_if", node.lineno)


def _drop_guard(
    found: list[Mutant],
    path: str,
    source: str,
    raw: bytes,
    starts: list[int],
    lines: frozenset[int],
    parents: dict[int, ast.AST],
    node: ast.If,
) -> None:
    if node.lineno not in lines or node.orelse or len(node.body) != 1:
        return
    if not isinstance(node.body[0], (ast.Raise, ast.Return)):
        return
    span = _statement_span(raw, starts, node)
    if span is None:
        return
    start, end, indent = span
    replacement = indent + "pass\n" if _needs_pass(parents.get(id(node)), node) else ""
    _emit(found, path, source, raw, start, end, replacement, "drop_guard", node.lineno)


def _return_none(
    found: list[Mutant],
    path: str,
    source: str,
    raw: bytes,
    starts: list[int],
    lines: frozenset[int],
    node: ast.Return,
) -> None:
    if not _touches(node, lines) or node.value is None:
        return
    if isinstance(node.value, ast.Constant) and node.value.value is None:
        return
    span = _span_bytes(raw, starts, node)
    if span is None:
        return
    _emit(found, path, source, raw, span[0], span[1], "return None", "return_none", node.lineno)


def _off_by_one(
    found: list[Mutant],
    path: str,
    source: str,
    raw: bytes,
    starts: list[int],
    lines: frozenset[int],
    parents: dict[int, ast.AST],
    node: ast.Constant,
) -> None:
    if type(node.value) is not int or not _touches(node, lines):
        return
    if _in_annotation(node, parents):
        return
    span = _span_bytes(raw, starts, node)
    if span is None:
        return
    for delta in (1, -1):
        _emit(found, path, source, raw, span[0], span[1], str(node.value + delta), "off_by_one", node.lineno)


def _script_candidates(path: str, source: str, lines: frozenset[int]) -> list[Mutant]:
    parsed = as_source_file(path, source)
    if parsed is None:
        return []
    root = parse_root(parsed)
    if root is None or root.has_error:
        return []
    raw = source.encode("utf-8")
    found: list[Mutant] = []
    for node in walk_tree(root):
        if _in_type(node) or not _script_line(node, lines):
            continue
        if node.type == "binary_expression":
            _script_binary(found, path, source, raw, node)
        elif node.type == "if_statement":
            _script_negate_if(found, path, source, raw, node)
            _script_drop_guard(found, path, source, raw, node)
        elif node.type == "return_statement":
            _script_return(found, path, source, raw, node)
        elif node.type == "number":
            _script_off_by_one(found, path, source, raw, node)
        elif node.type == "await_expression":
            _script_remove_await(found, path, source, raw, node)
    return [item for item in found if not _script_has_error(path, item.source)]


def _script_binary(found: list[Mutant], path: str, source: str, raw: bytes, node: Node) -> None:
    for child in node.children:
        if child.is_named:
            continue
        token = node_text(child)
        flipped = _TS_CMP.get(token)
        if flipped is None and token in {"&&", "||"}:
            flipped = "||" if token == "&&" else "&&"
            operator = "bool_flip"
        elif flipped is not None:
            operator = "cmp_flip"
        else:
            continue
        _emit_bytes(
            found,
            path,
            source,
            raw,
            child.start_byte,
            child.end_byte,
            flipped,
            operator,
            child.start_point[0] + 1,
        )


def _script_negate_if(found: list[Mutant], path: str, source: str, raw: bytes, node: Node) -> None:
    condition = node.child_by_field_name("condition")
    if condition is None:
        return
    inner = condition.named_children[0] if condition.named_children else condition
    if inner.type == "unary_expression" and any(child.type == "!" for child in inner.children):
        operand = next((child for child in inner.named_children), None)
        if operand is None:
            return
        new = node_text(operand)
        start, end = inner.start_byte, inner.end_byte
    else:
        new = "!(" + node_text(inner) + ")"
        start, end = inner.start_byte, inner.end_byte
    _emit_bytes(found, path, source, raw, start, end, new, "negate_if", node.start_point[0] + 1)


def _script_drop_guard(found: list[Mutant], path: str, source: str, raw: bytes, node: Node) -> None:
    if node.child_by_field_name("alternative") is not None:
        return
    consequence = node.child_by_field_name("consequence")
    if consequence is None or not _is_guard_body(consequence):
        return
    _emit_bytes(
        found,
        path,
        source,
        raw,
        node.start_byte,
        node.end_byte,
        "",
        "drop_guard",
        node.start_point[0] + 1,
    )


def _script_return(found: list[Mutant], path: str, source: str, raw: bytes, node: Node) -> None:
    value = next((child for child in node.named_children), None)
    if value is None or node_text(value) in {"undefined", "null"}:
        return
    _emit_bytes(
        found,
        path,
        source,
        raw,
        node.start_byte,
        node.end_byte,
        "return undefined;",
        "return_none",
        node.start_point[0] + 1,
    )


def _script_off_by_one(found: list[Mutant], path: str, source: str, raw: bytes, node: Node) -> None:
    text = node_text(node)
    if not text.isdigit():
        return
    value = int(text)
    line = node.start_point[0] + 1
    for delta in (1, -1):
        _emit_bytes(found, path, source, raw, node.start_byte, node.end_byte, str(value + delta), "off_by_one", line)


def _script_remove_await(found: list[Mutant], path: str, source: str, raw: bytes, node: Node) -> None:
    inner = next((child for child in node.named_children), None)
    if inner is None:
        return
    _emit_bytes(
        found,
        path,
        source,
        raw,
        node.start_byte,
        node.end_byte,
        node_text(inner),
        "remove_await",
        node.start_point[0] + 1,
    )


def _emit(
    found: list[Mutant],
    path: str,
    source: str,
    raw: bytes,
    start: int,
    end: int,
    new: str,
    operator: str,
    line: int,
) -> None:
    _emit_bytes(found, path, source, raw, start, end, new, operator, line, check_python=True)


def _emit_bytes(
    found: list[Mutant],
    path: str,
    source: str,
    raw: bytes,
    start: int,
    end: int,
    new: str,
    operator: str,
    line: int,
    *,
    check_python: bool = False,
) -> None:
    if start < 0 or end < start or end > len(raw):
        return
    updated = raw[:start] + new.encode("utf-8") + raw[end:]
    try:
        text = updated.decode("utf-8")
    except UnicodeDecodeError:
        return
    if text == source:
        return
    if check_python:
        try:
            compile(text, path, "exec")
        except SyntaxError:
            return
    found.append(Mutant(operator, path, line, text))


def _script_has_error(path: str, source: str) -> bool:
    parsed = as_source_file(path, source)
    if parsed is None:
        return True
    root = parse_root(parsed)
    return root is None or root.has_error


def _is_guard_body(node: Node) -> bool:
    if node.type in {"return_statement", "throw_statement"}:
        return True
    if node.type != "statement_block":
        return False
    statements = [child for child in node.named_children if child.type != "comment"]
    return len(statements) == 1 and statements[0].type in {"return_statement", "throw_statement"}


def _script_line(node: Node, lines: frozenset[int]) -> bool:
    return (node.start_point[0] + 1) in lines


def _in_type(node: Node) -> bool:
    current = node.parent
    while current is not None:
        if current.type in _TYPE_ANCESTORS:
            return True
        current = current.parent
    return False


def _touches(node: ast.AST, lines: frozenset[int]) -> bool:
    start = getattr(node, "lineno", None)
    end = getattr(node, "end_lineno", None) or start
    if not isinstance(start, int) or not isinstance(end, int):
        return False
    return any(line in lines for line in range(start, end + 1))


def _parents(tree: ast.AST) -> dict[int, ast.AST]:
    parents: dict[int, ast.AST] = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parents[id(child)] = parent
    return parents


def _in_annotation(node: ast.AST, parents: dict[int, ast.AST]) -> bool:
    current = parents.get(id(node))
    while current is not None:
        annotation = getattr(current, "annotation", None)
        returns = getattr(current, "returns", None)
        if annotation is not None and _within(annotation, node):
            return True
        if returns is not None and _within(returns, node):
            return True
        current = parents.get(id(current))
    return False


def _within(root: ast.AST, node: ast.AST) -> bool:
    return any(item is node for item in ast.walk(root))


def _needs_pass(parent: ast.AST | None, node: ast.If) -> bool:
    body = getattr(parent, "body", None)
    if not isinstance(parent, _NEEDS_BODY) or not isinstance(body, list):
        return False
    return not any(stmt is not node for stmt in body)


def _span_bytes(raw: bytes, starts: list[int], node: ast.AST) -> tuple[int, int] | None:
    lineno = getattr(node, "lineno", None)
    end_lineno = getattr(node, "end_lineno", None)
    col = getattr(node, "col_offset", None)
    end_col = getattr(node, "end_col_offset", None)
    if not all(isinstance(value, int) for value in (lineno, end_lineno, col, end_col)):
        return None
    if lineno < 1 or end_lineno < 1 or lineno > len(starts) or end_lineno > len(starts):
        return None
    return starts[lineno - 1] + col, starts[end_lineno - 1] + end_col


def _statement_span(raw: bytes, starts: list[int], node: ast.AST) -> tuple[int, int, str] | None:
    span = _span_bytes(raw, starts, node)
    if span is None:
        return None
    start, end = span
    line_start = raw.rfind(b"\n", 0, start) + 1
    indent = raw[line_start:start].decode("utf-8")
    if indent.strip():
        indent = ""
    else:
        start = line_start
    if end < len(raw) and raw[end : end + 1] == b"\n":
        end += 1
    return start, end, indent


def _line_starts(raw: bytes) -> list[int]:
    starts = [0]
    for index, value in enumerate(raw):
        if value == 0x0A:
            starts.append(index + 1)
    return starts
