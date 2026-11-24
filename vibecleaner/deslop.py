"""Detect deslop: weak types, debug leftovers, narrating comments, legacy copies,
pointless catches, unused privates, duplicated bodies, and import cycles.

Per-file rules run from ``detect_deslop``. Cross-file duplicates, import cycles,
and legacy siblings that live in another file of the same directory run from
``detect_repo_deslop``. Test, fixture, declaration, minified, and migration
paths are skipped. A hit has to be something a later cleanup pass can delete
without changing behavior.
"""

from __future__ import annotations

import hashlib
import posixpath
import re
from collections import Counter, defaultdict
from collections.abc import Callable, Iterator
from pathlib import PurePosixPath

from tree_sitter import Node

from vibecleaner.models import Finding, Language, SourceFile
from vibecleaner.ts_parse import (
    callee_name,
    line_text,
    node_text,
    parser_for,
    python_string,
    script_string,
    walk_tree,
)

__all__ = [
    "CONCERN_BRIEFS",
    "DESLOP_CONCERNS",
    "build_cross_refs",
    "detect_deslop",
    "detect_repo_deslop",
    "slop_score",
]

# Cleanup lanes. ``types`` is a lane with no detector yet.
DESLOP_CONCERNS: dict[str, str] = {
    "D9.weak_type": "weak-types",
    "D9.debug_leftover": "ai-slop",
    "D9.larp_comment": "ai-slop",
    "D9.legacy_fallback": "legacy",
    "D9.pointless_catch": "defensive-code",
    "D9.unused_private": "dead-code",
    "D9.duplicate_function": "dedupe",
    "D9.circular_import": "cycles",
    "D9.mocked_production": "ai-slop",
    "D9.missing_dependency": "legacy",
    "D9.slopsquat": "legacy",
    "D9.contract_drift": "ai-slop",
    "D9.migration_hazard": "legacy",
    "D9.env_parity": "ai-slop",
    "D9.assertion_gap": "ai-slop",
    "D9.flaky_test": "ai-slop",
    "D9.prompt_leak": "ai-slop",
    "D9.missing_telemetry": "ai-slop",
    "D9.loop_io": "defensive-code",
    "D9.boundary_schema": "defensive-code",
    "D9.graphql_drift": "ai-slop",
    "D9.registry_missing": "legacy",
    "D6a.silent_exception": "defensive-code",
    "D6a.deprecated_sdk": "legacy",
    "D6a.passthrough_wrapper": "dedupe",
    "D6a.god_file": "dedupe",
    "D6a.implicit_coupling": "dedupe",
    "D6a.layer_folder": "dedupe",
    "D6a.illegal_state": "weak-types",
    "D6a.shotgun_surgery": "dedupe",
    "D6a.layering_violation": "cycles",
    "D6b.hardcoded_mock_stub": "ai-slop",
    "D6c.llm_prose": "ai-slop",
}

CONCERN_BRIEFS: dict[str, str] = {
    "dedupe": (
        "Keep one copy of an identical body or pass-through wrapper, and split a god file "
        "only when each extracted module preserves the behavior callers already see."
    ),
    "types": (
        "Merge type aliases and interfaces that describe the same shape into one declaration "
        "without widening or narrowing the values they accept."
    ),
    "dead-code": (
        "Delete a private function or class only when the name has no reference in this file "
        "or the rest of the repo, and leave exported, decorated, and dunder entry points alone."
    ),
    "cycles": (
        "Break a circular import by moving the shared symbol into a module both sides can import, "
        "or by inverting the dependency, without changing which module runs first at runtime."
    ),
    "weak-types": (
        "Replace any, as-any, as-unknown-as, and bare type-ignore with the real type, "
        "and do not touch a value the checker already accepts."
    ),
    "defensive-code": (
        "Remove a catch that only rethrows or swallows the error, and keep a handler that logs, "
        "translates, or cleans up."
    ),
    "legacy": (
        "Delete a backup file or an old, legacy, or v1 definition only when a current sibling "
        "is the one callers use, and keep the only remaining implementation."
    ),
    "ai-slop": (
        "Remove debugger leftovers, placeholder comments, fake production stubs, and prose tics, "
        "and do not change code that already does the real work."
    ),
}

_CODE = frozenset({Language.PYTHON, Language.TYPESCRIPT, Language.TSX, Language.JAVASCRIPT})
_TEST_PARTS = frozenset({"tests", "__tests__", "fixtures"})
_TOOL_DIRS = frozenset({"scripts", "bin", "cli"})
_BARE_ANY = frozenset({"Any", "typing.Any"})
_ANNOTATION_OWNERS = frozenset({"typed_parameter", "typed_default_parameter", "assignment"})
_TS_EXTENSIONS = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs")
_MIN_DUPLICATE_LINES = 8
_SLOP_WEIGHT = {"low": 1, "medium": 3, "high": 6, "critical": 6}
_SLOP_BUDGET_PER_FILE = 10

_MARKER = re.compile(
    r"(?i)(?:^|_)(old|legacy|deprecated|bak|backup|copy|orig|unused)(?:_|$)"
)
_CAMEL_SUFFIX = re.compile(r"(?:_old|Old|Legacy)$")
_VERSION_V1 = re.compile(r"^(?P<base>.+)(?:_v1|V1)$")
_HIGHER_VERSION = re.compile(r"^(?P<base>.+)(?:_v(?P<num>[2-9]\d*)|V(?P<num2>[2-9]\d*))$")
_TYPE_IGNORE = re.compile(r"^#\s*type:\s*ignore(?!\s*\[)", re.IGNORECASE)
_TS_IGNORE = re.compile(r"@ts-ignore\b", re.IGNORECASE)
_TS_NOCHECK = re.compile(r"@ts-nocheck\b", re.IGNORECASE)
_TS_EXPECT = re.compile(r"@ts-expect-error\b", re.IGNORECASE)
_ESLINT_ANY = re.compile(r"eslint-disable[\s\S]{0,240}no-explicit-any", re.IGNORECASE)
_WORD = re.compile(r"[A-Za-z0-9_]+")
_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_LARP = re.compile(
    r"(?im)"
    r"\btemporary\s+(?:fix|workaround|hack|solution)\b"
    r"|\bquick\s+(?:fix|hack)\b"
    r"|^hack\b"
    r"|\bno longer\s+(?:used|needed)\b"
    r"|\bold\s+(?:implementation|approach|version|code)\b"
    r"|\bnew\s+(?:implementation|approach|version)\b"
    r"|\b(?:changed|updated|refactored|switched|migrated)\s+(?:to|from)\s"
    r"|\breplaced\s+(?:with|by)\b"
    r"|\bwas\s+(?:removed|changed)\b"
    r"|\bin a real\s(?:app|application|implementation|world|system)\b"
    r"|\bin production,?\s(?:you|we)\s(?:would|should)\b"
    r"|\bsimplified\s(?:version|implementation)\b"
    r"|\bplaceholder\s(?:implementation|logic|data)\b"
    r"|\bmock implementation\b"
    r"|\b(?:this|here)\s(?:is|we)\s(?:just\s)?(?:a\s)?(?:simple|basic)\s(?:example|implementation)\b"
    r"|\bas requested\b"
    r"|\bTODO:\s*implement\b"
    r"|\bFIXME:\s*implement\b"
    r"|\bimplement\s(?:this|me)\slater\b"
    r"|\badd\s(?:real|proper)\s.{0,20}\slater\b"
    r"|^[=\-~*]{10,}$"
    r"|^[=\-]{4,}\s+[A-Z0-9 _/]{3,}\s+[=\-]{4,}$"
    r"|^step\s+\d+\s*:"
    r"|^(?:main|core|business)\s+logic\.?$"
    r"|^helper\s+functions?\.?$"
    r"|^error\s+handling\.?$"
    r"|^note:\s*this\s+is\s+important\.?$"
    r"|^[\u2705\U0001f680\U0001f512\u2728\U0001f4a1\U0001f525]"
    r"|^end\s+(?:of\s+)?(?:if|for|while|loop|try|catch|function|method|class|block)\.?$"
)
_DIRECTIVE = re.compile(
    r"(?i)(\bnoqa\b|\btype\s*:|eslint|prettier-ignore|\blicense\b|\bcopyright\b|\bspdx\b|all rights reserved|\(c\))"
)
_KEPT_CALLS = frozenset({"call", "call_expression"})
_PY_SKIP_STATEMENTS = frozenset({"comment", "pass_statement"})
_TS_SKIP_STATEMENTS = frozenset({"comment", "empty_statement"})


class _Def:
    __slots__ = ("directory", "file", "line", "name", "scope")

    def __init__(self, name: str, file: str, line: int, scope: str, directory: str) -> None:
        self.name = name
        self.file = file
        self.line = line
        self.scope = scope
        self.directory = directory


class _Fn:
    __slots__ = ("file", "language", "line", "name", "snippet", "tokens")

    def __init__(
        self,
        file: str,
        line: int,
        name: str,
        language: str,
        snippet: str,
        tokens: tuple[str, ...],
    ) -> None:
        self.file = file
        self.line = line
        self.name = name
        self.language = language
        self.snippet = snippet
        self.tokens = tokens


class CrossRefIndex:
    """How many scanned files contain each identifier-like token."""

    __slots__ = ("_files", "_per_file")

    def __init__(self, files: Counter[str], per_file: dict[str, set[str]]) -> None:
        self._files = files
        self._per_file = per_file

    def mentioned(self, path: str, name: str) -> bool:
        own = self._per_file.get(path)
        present = own is not None and name in own
        return self._files.get(name, 0) > (1 if present else 0)


def build_cross_refs(files: list[SourceFile]) -> CrossRefIndex:
    """Identifier tokens for ``files``, one pass over the scan."""
    per_file: dict[str, set[str]] = {}
    freq: Counter[str] = Counter()
    for source in files:
        tokens = set(_IDENT.findall(source.text))
        existing = per_file.get(source.path)
        if existing is None:
            per_file[source.path] = tokens
            freq.update(tokens)
            continue
        freq.update(tokens.difference(existing))
        existing.update(tokens)
    return CrossRefIndex(freq, per_file)


def detect_deslop(
    source: SourceFile,
    all_text: str | None = None,
    cross_refs: CrossRefIndex | None = None,
) -> list[Finding]:
    """Per-file deslop rules.

    ``cross_refs`` is the scan-wide index from :func:`build_cross_refs`.
    ``all_text`` is other files' raw text. A private name is kept when either
    one shows it outside this file, or when this file uses it as a string
    constant. With neither argument, only this file's code identifiers count.
    """
    if _is_test_path(source.path):
        return []
    findings: list[Finding] = []
    if _is_backup_name(source.path):
        findings.append(
            _finding(
                "D9.legacy_fallback",
                source,
                1,
                f"Legacy backup file {PurePosixPath(source.path).name}",
            )
        )
    if source.language not in _CODE or _is_generated_path(source.path):
        return _dedupe(findings)
    root = _parse(source)
    if root is None:
        return _dedupe(findings)
    findings.extend(_weak_types(source, root))
    findings.extend(_debug_leftovers(source, root))
    findings.extend(_larp_comments(source, root))
    findings.extend(_legacy_hits([source], cross_file_only=False))
    findings.extend(_pointless_catches(source, root))
    findings.extend(_unused_private(source, root, all_text, cross_refs))
    return _dedupe(findings)


def detect_repo_deslop(files: list[SourceFile]) -> list[Finding]:
    """Cross-file duplicates, import cycles, and legacy siblings in the same directory."""
    findings = _duplicate_functions(files)
    findings.extend(_circular_imports(files))
    findings.extend(_legacy_hits(files, cross_file_only=True))
    return _dedupe(findings)


def slop_score(findings: list[Finding], files_scanned: int) -> int:
    """Return 0..100, where 100 means the scan has no slop findings.

    Only ``Category.SLOP`` findings count. Weights are low=1, medium=3, high=6
    (critical counts as 6). The penalty is
    ``min(100, round_half_up(100 * total_weight / (files_scanned * 10)))``,
    so ten weight-points per scanned file scores 0. Zero files scores 100.
    """
    if files_scanned <= 0:
        return 100
    total = 0
    for finding in findings:
        if finding.category.value != "slop":
            continue
        total += _SLOP_WEIGHT.get(finding.severity.value, 1)
    if total <= 0:
        return 100
    budget = files_scanned * _SLOP_BUDGET_PER_FILE
    penalty = min(100, (total * 100 + budget // 2) // budget)
    return 100 - penalty


def _weak_types(source: SourceFile, root: Node) -> list[Finding]:
    if source.language == Language.PYTHON:
        return _python_weak_types(source, root)
    return _script_weak_types(source, root)


def _python_weak_types(source: SourceFile, root: Node) -> list[Finding]:
    findings: list[Finding] = []
    for node in walk_tree(root):
        if node.type == "comment" and _TYPE_IGNORE.match(node_text(node).strip()):
            findings.append(_finding("D9.weak_type", source, _line(node), "Bare # type: ignore"))
        elif node.type == "call" and _is_cast_any(node):
            findings.append(_finding("D9.weak_type", source, _line(node), "cast(Any, ...) hides the type"))
        else:
            annotation = _bare_any_annotation(node)
            if annotation is not None:
                findings.append(_finding("D9.weak_type", source, _line(annotation), "Annotation is bare Any"))
    return findings


def _bare_any_annotation(node: Node) -> Node | None:
    if node.type == "function_definition":
        target = node.child_by_field_name("return_type")
    elif node.type in _ANNOTATION_OWNERS:
        target = node.child_by_field_name("type")
    else:
        return None
    if target is not None and _is_bare_any(target):
        return target
    return None


def _is_bare_any(node: Node | None) -> bool:
    if node is None or node.type != "type" or len(node.named_children) != 1:
        return False
    inner = node.named_children[0]
    if inner.type == "identifier":
        return node_text(inner) == "Any"
    if inner.type == "attribute":
        return callee_name(inner) == "typing.Any"
    if inner.type == "string":
        return python_string(inner) in _BARE_ANY
    return False


def _is_cast_any(node: Node) -> bool:
    func = node.child_by_field_name("function")
    if func is None or callee_name(func) not in {"cast", "typing.cast"}:
        return False
    args = node.child_by_field_name("arguments")
    if args is None or not args.named_children:
        return False
    first = args.named_children[0]
    if first.type == "identifier":
        return node_text(first) == "Any"
    if first.type == "attribute":
        return callee_name(first) in {"Any", "typing.Any"}
    return False


def _script_weak_types(source: SourceFile, root: Node) -> list[Finding]:
    findings: list[Finding] = []
    seen_any: set[int] = set()
    for node in walk_tree(root):
        line = _line(node)
        if node.type == "predefined_type" and node_text(node) == "any" and line not in seen_any:
            seen_any.add(line)
            findings.append(_finding("D9.weak_type", source, line, "Type uses any"))
        elif _is_outer_unknown_cast(node):
            findings.append(_finding("D9.weak_type", source, line, "Double cast through unknown"))
        elif node.type == "comment":
            findings.extend(_script_type_comments(source, node))
    return findings


def _is_outer_unknown_cast(node: Node) -> bool:
    if node.type != "as_expression":
        return False
    parent = node.parent
    if parent is not None and parent.type == "as_expression":
        return False
    types: list[Node] = []
    current: Node | None = node
    while current is not None and current.type == "as_expression":
        named = current.named_children
        if len(named) < 2:
            return False
        types.append(named[-1])
        current = named[0]
    if len(types) < 2:
        return False
    if current is not None and node_text(current) == "globalThis":
        # `globalThis as unknown as { prisma?: PrismaClient }` is the documented
        # dev-server singleton pattern for Prisma and similar clients.
        return False
    return any(item.type == "predefined_type" and node_text(item) == "unknown" for item in types)


def _script_type_comments(source: SourceFile, node: Node) -> list[Finding]:
    text = node_text(node)
    findings: list[Finding] = []
    line = _line(node)
    if _TS_IGNORE.search(text):
        findings.append(_finding("D9.weak_type", source, line, "@ts-ignore hides a type error"))
    if _TS_NOCHECK.search(text):
        findings.append(_finding("D9.weak_type", source, line, "@ts-nocheck hides type errors"))
    if _ESLINT_ANY.search(text):
        findings.append(_finding("D9.weak_type", source, line, "eslint-disable for no-explicit-any"))
    expect = _TS_EXPECT.search(text)
    if expect is not None and len(_WORD.findall(text[expect.end() :])) < 3:
        findings.append(_finding("D9.weak_type", source, line, "@ts-expect-error without an explanation"))
    return findings


def _debug_leftovers(source: SourceFile, root: Node) -> list[Finding]:
    if source.language == Language.PYTHON:
        return _python_debug(source, root)
    return _script_debug(source, root)


def _python_debug(source: SourceFile, root: Node) -> list[Finding]:
    findings: list[Finding] = []
    for node in walk_tree(root):
        if node.type == "call" and _python_debug_call(node):
            findings.append(
                _finding("D9.debug_leftover", source, _line(node), f"Debug leftover: {callee_name(node)}")
            )
        elif node.type in {"import_statement", "import_from_statement"}:
            module = _imported_root(node)
            if module in {"pdb", "ipdb"}:
                findings.append(
                    _finding("D9.debug_leftover", source, _line(node), f"Debug leftover: import {module}")
                )
    return findings


def _python_debug_call(node: Node) -> bool:
    name = callee_name(node)
    return name in {"breakpoint", "pdb.set_trace", "ipdb.set_trace"}


def _imported_root(node: Node) -> str:
    if node.type == "import_statement":
        for child in node.children:
            target = child
            if child.type == "aliased_import":
                target = next((item for item in child.children if item.type == "dotted_name"), None)
            if target is not None and target.type == "dotted_name":
                parts = _dotted_parts(target)
                return parts[0] if parts else ""
        return ""
    for child in node.children:
        if child.type == "import":
            break
        if child.type == "dotted_name":
            parts = _dotted_parts(child)
            return parts[0] if parts else ""
        if child.type == "relative_import":
            return ""
    return ""


def _script_debug(source: SourceFile, root: Node) -> list[Finding]:
    findings: list[Finding] = []
    console_ok = _flag_console(source.path)
    for node in walk_tree(root):
        if node.type == "debugger_statement":
            findings.append(_finding("D9.debug_leftover", source, _line(node), "Debug leftover: debugger"))
        elif console_ok and node.type == "call_expression" and _is_console_debug(node):
            prop = _member_property(node.child_by_field_name("function"))
            findings.append(
                _finding("D9.debug_leftover", source, _line(node), f"Debug leftover: console.{prop}")
            )
    return findings


def _is_console_debug(node: Node) -> bool:
    func = node.child_by_field_name("function")
    if func is None or func.type != "member_expression":
        return False
    obj = func.child_by_field_name("object")
    prop = func.child_by_field_name("property")
    if obj is None or prop is None or obj.type != "identifier":
        return False
    return node_text(obj) == "console" and node_text(prop) in {"log", "debug"}


def _member_property(node: Node | None) -> str:
    if node is None:
        return "log"
    prop = node.child_by_field_name("property")
    return node_text(prop) if prop is not None else "log"


def _flag_console(path: str) -> bool:
    pure = PurePosixPath(path)
    if ".config." in pure.name or pure.stem in {"cli", "config"}:
        return False
    return all(part not in _TOOL_DIRS for part in pure.parts[:-1])


def _larp_comments(source: SourceFile, root: Node) -> list[Finding]:
    findings: list[Finding] = []
    for node in _walk_all(root):
        if node.type != "comment":
            continue
        raw = node_text(node)
        if raw.startswith("#!"):
            continue
        body = _comment_body(raw)
        if not body or _DIRECTIVE.search(body):
            continue
        match = _LARP.search(body)
        if match is None:
            continue
        phrase = " ".join(match.group(0).split())
        findings.append(
            _finding(
                "D9.larp_comment",
                source,
                _line(node),
                f"Comment narrates in-motion work: {phrase[:80]}",
            )
        )
    return findings


def _comment_body(raw: str) -> str:
    text = raw.strip()
    if text.startswith("#"):
        return text[1:].strip()
    if text.startswith("//"):
        return text[2:].strip()
    if text.startswith("/*"):
        text = text[2:]
        if text.endswith("*/"):
            text = text[:-2]
        lines = [re.sub(r"^\s*\*?", "", line).strip() for line in text.splitlines()]
        return "\n".join(line for line in lines if line).strip()
    return text


def _pointless_catches(source: SourceFile, root: Node) -> list[Finding]:
    findings: list[Finding] = []
    for node in walk_tree(root):
        if node.type != "try_statement":
            continue
        if source.language == Language.PYTHON:
            pointless = _python_try_pointless(node)
        else:
            pointless = _script_try_pointless(node)
        if pointless:
            findings.append(_finding("D9.pointless_catch", source, _line(node), "Catch block only rethrows"))
    return findings


def _python_try_pointless(node: Node) -> bool:
    handlers = [child for child in node.named_children if child.type == "except_clause"]
    if not handlers or not all(_python_handler_pointless(handler) for handler in handlers):
        return False
    for child in node.named_children:
        if child.type in {"else_clause", "finally_clause"} and _clause_does_work(child, _PY_SKIP_STATEMENTS):
            return False
    return True


def _python_handler_pointless(clause: Node) -> bool:
    body = next((child for child in clause.named_children if child.type == "block"), None)
    if body is None:
        return False
    statements = [child for child in body.named_children if child.type != "comment"]
    if len(statements) != 1 or statements[0].type != "raise_statement":
        return False
    raised = [child for child in statements[0].children if child.type not in {"raise", "comment"}]
    if not raised:
        return True
    if len(raised) != 1 or raised[0].type != "identifier":
        return False
    alias = _except_alias(clause)
    return alias is not None and node_text(raised[0]) == alias


def _except_alias(clause: Node) -> str | None:
    pattern = next((child for child in clause.named_children if child.type == "as_pattern"), None)
    if pattern is None:
        return None
    target = next((child for child in pattern.named_children if child.type == "as_pattern_target"), None)
    if target is None:
        return None
    ident = next((child for child in target.children if child.type == "identifier"), None)
    if ident is None:
        return None
    return node_text(ident)


def _script_try_pointless(node: Node) -> bool:
    catches = [child for child in node.named_children if child.type == "catch_clause"]
    if len(catches) != 1 or not _script_catch_pointless(catches[0]):
        return False
    for child in node.named_children:
        if child.type == "finally_clause" and _clause_does_work(child, _TS_SKIP_STATEMENTS):
            return False
    return True


def _script_catch_pointless(clause: Node) -> bool:
    binding = next((child for child in clause.children if child.type == "identifier"), None)
    body = next((child for child in clause.named_children if child.type == "statement_block"), None)
    if binding is None or body is None:
        return False
    statements = [child for child in body.named_children if child.type not in _TS_SKIP_STATEMENTS]
    if len(statements) != 1 or statements[0].type != "throw_statement":
        return False
    thrown = statements[0].named_children
    return len(thrown) == 1 and thrown[0].type == "identifier" and node_text(thrown[0]) == node_text(binding)


def _clause_does_work(clause: Node, skip: frozenset[str]) -> bool:
    for child in clause.named_children:
        block = child if child.type in {"block", "statement_block"} else None
        if block is None:
            if child.type not in skip:
                return True
            continue
        for stmt in block.named_children:
            if stmt.type not in skip:
                return True
    return False


def _unused_private(
    source: SourceFile,
    root: Node,
    all_text: str | None,
    cross_refs: CrossRefIndex | None,
) -> list[Finding]:
    if PurePosixPath(source.path).name == "__init__.py":
        return []
    if source.language == Language.PYTHON:
        return _python_unused(source, root, all_text, cross_refs)
    return _script_unused(source, root, all_text, cross_refs)


def _python_unused(
    source: SourceFile,
    root: Node,
    all_text: str | None,
    cross_refs: CrossRefIndex | None,
) -> list[Finding]:
    exported = _dunder_all(root)
    if exported is not None and "*" in exported:
        return []
    findings: list[Finding] = []
    counts: Counter[str] | None = None
    strings: set[str] = set()
    for node in walk_tree(root):
        if node.type not in {"function_definition", "class_definition"}:
            continue
        if not _is_module_level(node) or _has_decorator(node):
            continue
        name_node = node.child_by_field_name("name")
        if name_node is None:
            continue
        name = node_text(name_node)
        if not _is_single_underscore(name):
            continue
        if exported is not None and name in exported:
            continue
        if counts is None:
            counts, strings = _code_name_counts(root, python=True)
        if counts[name] != 1 or name in strings:
            continue
        if _referenced_outside(name, source.path, all_text, cross_refs):
            continue
        kind = "class" if node.type == "class_definition" else "function"
        findings.append(
            _finding(
                "D9.unused_private",
                source,
                _line(node),
                f"Private {kind} {name} is never referenced",
                symbol=name,
            )
        )
    return findings


def _script_unused(
    source: SourceFile,
    root: Node,
    all_text: str | None,
    cross_refs: CrossRefIndex | None,
) -> list[Finding]:
    findings: list[Finding] = []
    candidates = _script_private_candidates(root)
    if candidates:
        counts, strings = _code_name_counts(root, python=False)
    else:
        counts, strings = Counter(), set()
    for name_node, line, kind in candidates:
        name = node_text(name_node)
        if counts[name] != 1 or name in strings:
            continue
        if _referenced_outside(name, source.path, all_text, cross_refs):
            continue
        findings.append(
            _finding(
                "D9.unused_private",
                source,
                line,
                f"Unexported {kind} {name} is never referenced",
                symbol=name,
            )
        )
    return findings


def _referenced_outside(
    name: str,
    path: str,
    all_text: str | None,
    cross_refs: CrossRefIndex | None,
) -> bool:
    if cross_refs is not None and cross_refs.mentioned(path, name):
        return True
    return all_text is not None and _mentioned(name, all_text)


def _script_private_candidates(root: Node) -> list[tuple[Node, int, str]]:
    found: list[tuple[Node, int, str]] = []
    for node in walk_tree(root):
        if node.type == "function_declaration" and _statement_is_top_level(node) and not _is_exported(node):
            name_node = node.child_by_field_name("name")
            body = node.child_by_field_name("body")
            if name_node is not None and name_node.type == "identifier" and body is not None:
                found.append((name_node, _line(node), "function"))
        elif node.type == "lexical_declaration" and _statement_is_top_level(node) and not _is_exported(node):
            found.extend(_arrow_candidates(node))
    return found


def _arrow_candidates(node: Node) -> list[tuple[Node, int, str]]:
    found: list[tuple[Node, int, str]] = []
    for child in node.named_children:
        if child.type != "variable_declarator":
            continue
        name_node = child.child_by_field_name("name")
        value = child.child_by_field_name("value")
        if name_node is None or name_node.type != "identifier" or value is None:
            continue
        if value.type not in {"arrow_function", "function_expression"}:
            continue
        found.append((name_node, _line(child), "function"))
    return found


def _dunder_all(root: Node) -> set[str] | None:
    found = False
    names: set[str] = set()
    for node in walk_tree(root):
        if node.type != "assignment":
            continue
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is None or node_text(left) != "__all__" or right is None:
            continue
        found = True
        literal = _string_collection(right)
        if literal is None:
            return {"*"}
        names.update(literal)
    if not found:
        return None
    return names


def _string_collection(node: Node) -> set[str] | None:
    if node.type not in {"list", "tuple", "set"}:
        return None
    names: set[str] = set()
    for child in node.named_children:
        if child.type != "string":
            return None
        content = "".join(node_text(item) for item in child.children if item.type == "string_content")
        names.add(content)
    return names


def _code_name_counts(root: Node, *, python: bool) -> tuple[Counter[str], set[str]]:
    """Code identifiers, plus tokens that occur inside string constants."""
    counts: Counter[str] = Counter()
    strings: set[str] = set()
    stack = [root]
    while stack:
        node = stack.pop()
        if node.type == "comment":
            continue
        if node.type == "string" or node.type == "template_string":
            content = python_string(node) if python else script_string(node)
            if content:
                strings.update(_IDENT.findall(content))
            if python and node.type == "string":
                stack.extend(child for child in node.children if child.type == "interpolation")
            elif node.type == "template_string":
                stack.extend(child for child in node.children if child.type == "template_substitution")
            continue
        if node.type in {"identifier", "type_identifier"}:
            counts[node_text(node)] += 1
        stack.extend(node.children)
    return counts, strings


def _mentioned(name: str, text: str) -> bool:
    return re.search(rf"(?<![A-Za-z0-9_]){re.escape(name)}(?![A-Za-z0-9_])", text) is not None


def _is_single_underscore(name: str) -> bool:
    return name.startswith("_") and not name.startswith("__") and name.isidentifier()


def _is_module_level(node: Node) -> bool:
    parent = node.parent
    if parent is not None and parent.type == "decorated_definition":
        parent = parent.parent
    return parent is not None and parent.type == "module"


def _has_decorator(node: Node) -> bool:
    parent = node.parent
    return parent is not None and parent.type == "decorated_definition"


def _is_exported(node: Node) -> bool:
    parent = node.parent
    return parent is not None and parent.type == "export_statement"


def _statement_is_top_level(node: Node) -> bool:
    parent = node.parent
    if parent is None:
        return False
    if parent.type == "program":
        return True
    return parent.type == "export_statement" and parent.parent is not None and parent.parent.type == "program"


def _legacy_hits(files: list[SourceFile], *, cross_file_only: bool) -> list[Finding]:
    pool: list[_Def] = []
    text_by_file: dict[str, str] = {}
    for source in files:
        if not _in_scope(source):
            continue
        root = _parse(source)
        if root is None:
            continue
        text_by_file[source.path] = source.text
        pool.extend(_collect_defs(source, root))
    findings: list[Finding] = []
    for item in pool:
        shape = _legacy_shape(item.name)
        if shape is None:
            continue
        siblings = _current_siblings(item, pool, cross_file_only=cross_file_only)
        if not siblings:
            continue
        sibling = min(siblings, key=lambda other: (other.file, other.line, other.name))
        text = text_by_file.get(item.file, "")
        findings.append(
            Finding(
                rule_id="D9.legacy_fallback",
                file=item.file,
                line=item.line,
                message=f"Legacy definition {item.name} duplicates {sibling.name}",
                symbol=item.name,
                snippet=line_text(text, item.line),
            )
        )
    return findings


def _collect_defs(source: SourceFile, root: Node) -> list[_Def]:
    if source.language == Language.PYTHON:
        return _python_defs(source, root)
    return _script_defs(source, root)


def _python_defs(source: SourceFile, root: Node) -> list[_Def]:
    found: list[_Def] = []
    directory = _directory(source.path)
    for node in walk_tree(root):
        if node.type not in {"function_definition", "class_definition"}:
            continue
        scope = _python_scope(node)
        name_node = node.child_by_field_name("name")
        if scope is None or name_node is None:
            continue
        found.append(_Def(node_text(name_node), source.path, _line(node), scope, directory))
    return found


def _python_scope(node: Node) -> str | None:
    parent = node.parent
    if parent is not None and parent.type == "decorated_definition":
        parent = parent.parent
    if parent is None:
        return None
    if parent.type == "module":
        return "module"
    if parent.type != "block" or parent.parent is None or parent.parent.type != "class_definition":
        return None
    name_node = parent.parent.child_by_field_name("name")
    if name_node is None:
        return None
    return f"class:{node_text(name_node)}"


def _script_defs(source: SourceFile, root: Node) -> list[_Def]:
    found: list[_Def] = []
    directory = _directory(source.path)
    for node in walk_tree(root):
        if node.type == "function_declaration" and _statement_is_top_level(node):
            _append_named(found, node, source.path, "module", directory)
        elif node.type == "class_declaration" and _statement_is_top_level(node):
            _append_named(found, node, source.path, "module", directory)
        elif node.type == "method_definition":
            class_name = _class_name_of_method(node)
            if class_name is not None:
                _append_named(found, node, source.path, f"class:{class_name}", directory)
        elif node.type == "lexical_declaration" and _statement_is_top_level(node):
            for name_node, line, _kind in _arrow_candidates(node):
                found.append(_Def(node_text(name_node), source.path, line, "module", directory))
    return found


def _append_named(found: list[_Def], node: Node, file: str, scope: str, directory: str) -> None:
    name_node = node.child_by_field_name("name")
    if name_node is None:
        return
    found.append(_Def(node_text(name_node), file, _line(node), scope, directory))


def _class_name_of_method(node: Node) -> str | None:
    body = node.parent
    if body is None or body.type != "class_body" or body.parent is None:
        return None
    name_node = body.parent.child_by_field_name("name")
    if name_node is None:
        return None
    return node_text(name_node)


def _current_siblings(item: _Def, pool: list[_Def], *, cross_file_only: bool) -> list[_Def]:
    found: list[_Def] = []
    if cross_file_only and item.name.startswith("_"):
        return found
    for other in pool:
        if other.file == item.file and other.line == item.line and other.name == item.name:
            continue
        if other.scope != item.scope or other.directory != item.directory:
            continue
        if cross_file_only and (other.file == item.file or other.name.startswith("_")):
            continue
        if not cross_file_only and other.file != item.file:
            continue
        if _is_current_sibling(item.name, other.name):
            found.append(other)
    return found


def _legacy_shape(name: str) -> tuple[set[str], int | None] | None:
    version = _VERSION_V1.match(name)
    if version:
        return {version.group("base")}, 1
    suffix = _CAMEL_SUFFIX.search(name)
    if suffix and suffix.start() > 0:
        return {name[: suffix.start()]}, None
    match = _MARKER.search(name)
    if match is None:
        return None
    raw = name[: match.start(1)] + name[match.end(1) :]
    raw = re.sub(r"_+", "_", raw).strip("_")
    if not raw:
        return None
    bases = {raw}
    if name.startswith("_") and not raw.startswith("_"):
        bases.add("_" + raw)
    return bases, None


def _is_current_sibling(legacy: str, other: str) -> bool:
    if legacy == other:
        return False
    shape = _legacy_shape(legacy)
    if shape is None:
        return False
    bases, _version = shape
    if other in bases and _legacy_shape(other) is None:
        return True
    higher = _HIGHER_VERSION.match(other)
    return higher is not None and higher.group("base") in bases


def _duplicate_functions(files: list[SourceFile]) -> list[Finding]:
    buckets: dict[str, list[_Fn]] = defaultdict(list)
    for source in files:
        if not _in_scope(source):
            continue
        root = _parse(source)
        if root is None:
            continue
        for fn in _function_bodies(source, root):
            digest = hashlib.sha256((fn.language + "\n" + "\n".join(fn.tokens)).encode("utf-8")).hexdigest()
            buckets[digest].append(fn)
    findings: list[Finding] = []
    for bucket in buckets.values():
        exact: dict[tuple[str, tuple[str, ...]], list[_Fn]] = defaultdict(list)
        for fn in bucket:
            exact[(fn.language, fn.tokens)].append(fn)
        for copies in exact.values():
            if len(copies) < 2:
                continue
            copies.sort(key=lambda item: (item.file, item.line, item.name))
            first = copies[0]
            for copy in copies[1:]:
                findings.append(
                    Finding(
                        rule_id="D9.duplicate_function",
                        file=copy.file,
                        line=copy.line,
                        message=f"Duplicate of {first.file}:{first.line}",
                        symbol=copy.name,
                        snippet=copy.snippet,
                    )
                )
    return findings


def _function_bodies(source: SourceFile, root: Node) -> list[_Fn]:
    found: list[_Fn] = []
    for name, line, body in _iter_bodies(source, root):
        statements = _body_statements(body, source.language)
        if _span_lines(statements) < _MIN_DUPLICATE_LINES or _trivial_body(statements):
            continue
        tokens = _normalize_body(body, source.language)
        if not tokens:
            continue
        found.append(
            _Fn(
                file=source.path,
                line=line,
                name=name,
                language=source.language.value,
                snippet=line_text(source.text, line),
                tokens=tokens,
            )
        )
    return found


def _iter_bodies(source: SourceFile, root: Node) -> list[tuple[str, int, Node]]:
    if source.language == Language.PYTHON:
        return _python_bodies(root)
    return _script_bodies(root)


def _python_bodies(root: Node) -> list[tuple[str, int, Node]]:
    found: list[tuple[str, int, Node]] = []
    for node in walk_tree(root):
        if node.type != "function_definition":
            continue
        name_node = node.child_by_field_name("name")
        body = node.child_by_field_name("body")
        if name_node is None or body is None:
            continue
        found.append((node_text(name_node), _line(node), body))
    return found


def _script_bodies(root: Node) -> list[tuple[str, int, Node]]:
    found: list[tuple[str, int, Node]] = []
    for node in walk_tree(root):
        if node.type in {"function_declaration", "method_definition"}:
            name_node = node.child_by_field_name("name")
            body = node.child_by_field_name("body")
            if name_node is not None and body is not None:
                found.append((node_text(name_node), _line(node), body))
        elif node.type == "variable_declarator":
            name_node = node.child_by_field_name("name")
            value = node.child_by_field_name("value")
            if name_node is None or name_node.type != "identifier" or value is None:
                continue
            if value.type not in {"arrow_function", "function_expression"}:
                continue
            body = value.child_by_field_name("body")
            if body is not None:
                found.append((node_text(name_node), _line(node), body))
    return found


def _body_statements(body: Node, language: Language) -> list[Node]:
    if body.type in {"block", "statement_block"}:
        statements = [child for child in body.named_children if child.type != "comment"]
    else:
        statements = [body]
    if language == Language.PYTHON and statements and _is_docstring(statements[0]):
        return statements[1:]
    return statements


def _is_docstring(node: Node) -> bool:
    return (
        node.type == "expression_statement"
        and len(node.named_children) == 1
        and node.named_children[0].type == "string"
    )


def _span_lines(statements: list[Node]) -> int:
    lines: set[int] = set()
    for stmt in statements:
        for line in range(stmt.start_point[0], stmt.end_point[0] + 1):
            lines.add(line)
    return len(lines)


def _trivial_body(statements: list[Node]) -> bool:
    if not statements:
        return True
    return all(stmt.type in {"return_statement", "pass_statement"} for stmt in statements)


def _normalize_body(body: Node, language: Language) -> tuple[str, ...]:
    """Rename local identifiers in appearance order.

    Keywords, operators, attribute names, and callee names stay. Literals keep
    a canonical value (quotes and numeric underscores removed) so two rate
    tables that differ only by constants are not the same body.
    """
    tokens: list[str] = []
    names: dict[str, str] = {}

    def local(name: str) -> str:
        if name not in names:
            names[name] = f"id{len(names)}"
        return names[name]

    def emit(node: Node) -> None:
        if node.type == "comment":
            return
        if language == Language.PYTHON and node.type == "expression_statement" and _leading_docstring(node, body):
            return
        if _pure_literal(node):
            tokens.append(_literal_token(node))
            return
        if node.child_count == 0:
            tokens.append(_leaf_token(node, local))
            return
        for child in node.children:
            emit(child)

    emit(body)
    return tuple(tokens)


def _leading_docstring(node: Node, body: Node) -> bool:
    if not _is_docstring(node):
        return False
    for child in body.named_children:
        if child.type == "comment":
            continue
        return child.id == node.id
    return False


def _pure_literal(node: Node) -> bool:
    if node.type in {"integer", "float", "number", "true", "false", "none", "null", "undefined"}:
        return True
    if node.type == "string":
        return all(child.type != "interpolation" for child in node.children)
    if node.type == "template_string":
        return all(child.type != "template_substitution" for child in node.children)
    if node.type == "concatenated_string":
        return all(_pure_literal(child) for child in node.named_children)
    return False


def _literal_token(node: Node) -> str:
    if node.type in {"integer", "float", "number"}:
        return "num:" + node_text(node).replace("_", "")
    if node.type in {"true", "false", "none", "null", "undefined"}:
        return "lit:" + node.type
    if node.type == "concatenated_string":
        return "str:" + "".join(_literal_value(child) for child in node.named_children)
    return "str:" + _literal_value(node)


def _literal_value(node: Node) -> str:
    pieces = [
        node_text(child)
        for child in node.children
        if child.type in {"string_content", "string_fragment"}
    ]
    return "".join(pieces)


def _leaf_token(node: Node, local: Callable[[str], str]) -> str:
    if node.type in {"string_content", "string_fragment"}:
        return "str:" + node_text(node)
    if node.type == "property_identifier":
        return "attr:" + node_text(node)
    if node.type == "type_identifier":
        return "type:" + node_text(node)
    if node.type == "identifier":
        if _kept_identifier(node):
            return "name:" + node_text(node)
        return "id:" + local(node_text(node))
    return "tok:" + node_text(node)


def _kept_identifier(node: Node) -> bool:
    parent = node.parent
    if parent is None:
        return False
    if parent.type == "attribute":
        attr = parent.child_by_field_name("attribute")
        return attr is not None and attr.id == node.id
    if parent.type == "member_expression":
        prop = parent.child_by_field_name("property")
        return prop is not None and prop.id == node.id
    if parent.type in _KEPT_CALLS:
        func = parent.child_by_field_name("function")
        return func is not None and func.id == node.id
    return False


def _circular_imports(files: list[SourceFile]) -> list[Finding]:
    scoped = [source for source in files if _in_scope(source)]
    py_index = _python_index(scoped)
    paths = {source.path for source in scoped}
    has_src = any(PurePosixPath(source.path).parts[:1] == ("src",) for source in scoped)
    edges: dict[str, dict[str, int]] = defaultdict(dict)
    snippets: dict[tuple[str, int], str] = {}
    graph: dict[str, list[str]] = {source.path: [] for source in scoped}
    for source in scoped:
        root = _parse(source)
        if root is None:
            continue
        if source.language == Language.PYTHON:
            imports = _python_imports(root, source.path, py_index)
        else:
            imports = _script_imports(root, source.path, paths, has_src)
        for target, line in imports:
            if target not in paths or target == source.path:
                continue
            current = edges[source.path].get(target)
            if current is None or line < current:
                edges[source.path][target] = line
                snippets[(source.path, line)] = line_text(source.text, line)
    for src, dests in edges.items():
        graph[src] = sorted(dests)
    findings: list[Finding] = []
    for component in _sccs(graph):
        members = set(component)
        if not _component_cycles(members, graph):
            continue
        start = min(members)
        cycle = _one_cycle(start, members, graph)
        if cycle is None or len(cycle) < 2:
            continue
        nxt = cycle[1]
        line = edges.get(cycle[0], {}).get(nxt, 1)
        chain = " -> ".join(cycle)
        findings.append(
            Finding(
                rule_id="D9.circular_import",
                file=cycle[0],
                line=line,
                message=chain,
                snippet=snippets.get((cycle[0], line), line_text("", line)),
            )
        )
    return findings


def _component_cycles(members: set[str], graph: dict[str, list[str]]) -> bool:
    if len(members) > 1:
        return True
    only = next(iter(members))
    return only in graph.get(only, [])


def _python_index(files: list[SourceFile]) -> dict[tuple[str, ...], str]:
    index: dict[tuple[str, ...], str] = {}
    for source in files:
        if source.language != Language.PYTHON:
            continue
        index[_module_key(source.path)] = source.path
    return index


def _module_key(path: str) -> tuple[str, ...]:
    parts = PurePosixPath(path).parts
    if parts[-1] == "__init__.py":
        return parts[:-1]
    return parts[:-1] + (PurePosixPath(path).stem,)


def _python_imports(root: Node, path: str, index: dict[tuple[str, ...], str]) -> list[tuple[str, int]]:
    found: list[tuple[str, int]] = []
    for node in walk_tree(root):
        if node.type not in {"import_statement", "import_from_statement"}:
            continue
        if _inside_function(node) or _inside_type_checking(node):
            continue
        line = _line(node)
        for target in _resolve_python_import(node, path, index):
            found.append((target, line))
    return found


def _resolve_python_import(node: Node, path: str, index: dict[tuple[str, ...], str]) -> list[str]:
    if node.type == "import_statement":
        hits: list[str] = []
        for child in node.children:
            dotted = child
            if child.type == "aliased_import":
                dotted = next((item for item in child.children if item.type == "dotted_name"), None)
            if dotted is not None and dotted.type == "dotted_name":
                hits.extend(_resolve_chain(_dotted_parts(dotted), index))
        return hits
    module, names = _from_parts(node)
    if module is None:
        return []
    if module.type == "relative_import":
        base = _relative_base(module, path)
    else:
        base = _dotted_parts(module)
    if base is None:
        return []
    hits = _resolve_chain(base, index)
    package = index.get(base)
    if package is not None and package.endswith("__init__.py"):
        for name in names:
            if name is None:
                continue
            hits.extend(_resolve_chain(base + (name,), index))
    elif not base:
        for name in names:
            if name is None:
                continue
            hits.extend(_resolve_chain((name,), index))
    else:
        for name in names:
            if name is None:
                continue
            submodule = base + (name,)
            if submodule in index:
                hits.extend(_resolve_chain(submodule, index))
    return hits


def _from_parts(node: Node) -> tuple[Node | None, list[str | None]]:
    module: Node | None = None
    names: list[str | None] = []
    seen_import = False
    for child in node.children:
        if child.type == "import" and not seen_import:
            seen_import = True
            continue
        if not seen_import:
            if child.type in {"dotted_name", "relative_import"}:
                module = child
            continue
        if child.type == "wildcard_import":
            names.append(None)
        elif child.type == "dotted_name":
            parts = _dotted_parts(child)
            names.append(parts[0] if parts else None)
        elif child.type == "aliased_import":
            dotted = next((item for item in child.children if item.type == "dotted_name"), None)
            if dotted is not None:
                parts = _dotted_parts(dotted)
                names.append(parts[0] if parts else None)
    return module, names


def _relative_base(node: Node, path: str) -> tuple[str, ...] | None:
    prefix = next((child for child in node.children if child.type == "import_prefix"), None)
    dots = node_text(prefix).count(".") if prefix is not None else 0
    dotted = next((child for child in node.children if child.type == "dotted_name"), None)
    extra = _dotted_parts(dotted) if dotted is not None else ()
    package = PurePosixPath(path).parts[:-1]
    up = dots - 1
    if up > len(package):
        return None
    return package[: len(package) - up] + extra


def _resolve_chain(parts: tuple[str, ...], index: dict[tuple[str, ...], str]) -> list[str]:
    """The most specific module that exists. Parent packages are not extra edges."""
    if not parts:
        return []
    best: str | None = None
    for size in range(1, len(parts) + 1):
        hit = index.get(parts[:size])
        if hit is not None:
            best = hit
    if best is None:
        return []
    return [best]


def _dotted_parts(node: Node) -> tuple[str, ...]:
    return tuple(node_text(child) for child in node.children if child.type == "identifier")


def _inside_function(node: Node) -> bool:
    parent = node.parent
    while parent is not None:
        if parent.type in {"function_definition", "lambda"}:
            return True
        parent = parent.parent
    return False


def _inside_type_checking(node: Node) -> bool:
    parent = node.parent
    while parent is not None:
        if parent.type == "if_statement" and _type_checking_consequence(node, parent):
            return True
        parent = parent.parent
    return False


def _type_checking_consequence(node: Node, statement: Node) -> bool:
    condition = statement.child_by_field_name("condition")
    if condition is None or not _is_type_checking(condition):
        return False
    consequence = next((child for child in statement.named_children if child.type == "block"), None)
    return consequence is not None and _contains(consequence, node)


def _is_type_checking(node: Node) -> bool:
    if node.type == "identifier":
        return node_text(node) == "TYPE_CHECKING"
    if node.type == "attribute":
        attr = node.child_by_field_name("attribute")
        return attr is not None and node_text(attr) == "TYPE_CHECKING"
    return False


def _contains(parent: Node, node: Node) -> bool:
    current: Node | None = node
    while current is not None:
        if current.id == parent.id:
            return True
        current = current.parent
    return False


def _script_imports(root: Node, path: str, files: set[str], has_src: bool) -> list[tuple[str, int]]:
    found: list[tuple[str, int]] = []
    for node in walk_tree(root):
        if node.type not in {"import_statement", "export_statement"}:
            continue
        if not _script_value_import(node):
            continue
        spec = _import_spec(node)
        if spec is None:
            continue
        target = _resolve_spec(spec, path, files, has_src)
        if target is not None:
            found.append((target, _line(node)))
    return found


def _script_value_import(node: Node) -> bool:
    if any(child.type == "type" for child in node.children):
        return False
    specifiers = [child for child in walk_tree(node) if child.type in {"import_specifier", "export_specifier"}]
    if not specifiers:
        return _import_spec(node) is not None
    return any(not any(child.type == "type" for child in spec.children) for spec in specifiers)


def _import_spec(node: Node) -> str | None:
    for child in node.children:
        if child.type == "string":
            return script_string(child)
    return None


def _resolve_spec(spec: str, importer: str, files: set[str], has_src: bool) -> str | None:
    bases: list[str] = []
    if spec.startswith("./") or spec.startswith("../"):
        joined = posixpath.normpath(posixpath.join(posixpath.dirname(importer), spec))
        if joined.startswith(".."):
            return None
        bases.append(joined)
    elif spec.startswith("@/"):
        rest = spec[2:]
        if has_src:
            bases.append(posixpath.normpath("src/" + rest))
        bases.append(posixpath.normpath(rest))
    else:
        return None
    for base in bases:
        hit = _resolve_base(base, files)
        if hit is not None:
            return hit
    return None


def _resolve_base(base: str, files: set[str]) -> str | None:
    suffix = PurePosixPath(base).suffix
    candidates: list[str] = []
    if suffix in _TS_EXTENSIONS:
        candidates.append(base)
        stem = str(PurePosixPath(base).with_suffix(""))
        for ext in _TS_EXTENSIONS:
            candidate = stem + ext
            if candidate not in candidates:
                candidates.append(candidate)
    else:
        for ext in _TS_EXTENSIONS:
            candidates.append(base + ext)
        for ext in (".ts", ".tsx", ".js", ".jsx"):
            candidates.append(base + "/index" + ext)
    for candidate in candidates:
        if candidate in files:
            return candidate
    return None


def _sccs(graph: dict[str, list[str]]) -> list[list[str]]:
    """Iterative Tarjan. Deep import chains stay off the Python call stack."""
    index = 0
    indices: dict[str, int] = {}
    lowlink: dict[str, int] = {}
    stack: list[str] = []
    onstack: set[str] = set()
    components: list[list[str]] = []
    for start in sorted(graph):
        if start in indices:
            continue
        frames: list[tuple[str, int]] = [(start, 0)]
        while frames:
            node, edge_index = frames[-1]
            if node not in indices:
                indices[node] = index
                lowlink[node] = index
                index += 1
                stack.append(node)
                onstack.add(node)
            dests = graph.get(node, [])
            if edge_index < len(dests):
                frames[-1] = (node, edge_index + 1)
                succ = dests[edge_index]
                if succ not in indices:
                    frames.append((succ, 0))
                elif succ in onstack:
                    lowlink[node] = min(lowlink[node], indices[succ])
                continue
            frames.pop()
            if lowlink[node] == indices[node]:
                component: list[str] = []
                while stack:
                    item = stack.pop()
                    onstack.discard(item)
                    component.append(item)
                    if item == node:
                        break
                components.append(component)
            if frames:
                parent = frames[-1][0]
                lowlink[parent] = min(lowlink[parent], lowlink[node])
    return components


def _one_cycle(start: str, members: set[str], graph: dict[str, list[str]]) -> list[str] | None:
    neighbors = {node: [succ for succ in graph.get(node, []) if succ in members] for node in members}
    path = [start]
    seen = {start}
    cursors = [0]
    while path:
        node = path[-1]
        dests = neighbors.get(node, [])
        if cursors[-1] < len(dests):
            succ = dests[cursors[-1]]
            cursors[-1] += 1
            if succ == start and len(path) > 1:
                return path + [start]
            if succ not in seen:
                seen.add(succ)
                path.append(succ)
                cursors.append(0)
            continue
        finished = path.pop()
        cursors.pop()
        if finished != start:
            seen.discard(finished)
    if start in neighbors.get(start, []):
        return [start, start]
    return None


def _in_scope(source: SourceFile) -> bool:
    return source.language in _CODE and not _is_test_path(source.path) and not _is_generated_path(source.path)


def _is_test_path(path: str) -> bool:
    pure = PurePosixPath(path)
    if any(part in _TEST_PARTS for part in pure.parts):
        return True
    name = pure.name
    if name == "conftest.py" or name.startswith("test_") or name.endswith("_test.py"):
        return True
    return ".test." in name or ".spec." in name


def _is_generated_path(path: str) -> bool:
    pure = PurePosixPath(path)
    name = pure.name
    if name.endswith(".d.ts") or name.endswith(".min.js"):
        return True
    return "migrations" in pure.parts


def _is_backup_name(path: str) -> bool:
    name = PurePosixPath(path).name.lower()
    if name.endswith((".bak", ".orig", ".backup")):
        return True
    if name.endswith("_old.py") or name.endswith("-old.ts") or name.endswith("-old.tsx"):
        return True
    if name.startswith("copy of "):
        return True
    return re.search(r" copy\.[^/]+$", name) is not None


def _directory(path: str) -> str:
    parent = PurePosixPath(path).parent.as_posix()
    return "" if parent == "." else parent


def _parse(source: SourceFile) -> Node | None:
    parser = parser_for(source)
    if parser is None or not source.text.strip():
        return None
    return parser.parse(source.text.encode("utf-8", errors="replace")).root_node


def _line(node: Node) -> int:
    return node.start_point[0] + 1


def _walk_all(node: Node) -> Iterator[Node]:
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(reversed(current.children))


def _finding(
    rule_id: str,
    source: SourceFile,
    line: int,
    message: str,
    *,
    symbol: str | None = None,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        file=source.path,
        line=line,
        message=message,
        symbol=symbol,
        snippet=line_text(source.text, line),
    )


def _dedupe(findings: list[Finding]) -> list[Finding]:
    ordered = sorted(findings, key=lambda finding: (finding.file, finding.line, finding.rule_id, finding.message))
    seen: set[tuple[str, str, int, str]] = set()
    unique: list[Finding] = []
    for finding in ordered:
        key = (finding.rule_id, finding.file, finding.line, finding.message)
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique
