"""Delete slop a detector can prove, then ask the host to finish what remains.

Proven edits are byte deletions and a few rewrites. A second run on the same
tree changes nothing. Security findings are left for ``scan``.
"""

from __future__ import annotations

import ast
import json
import os
import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from tree_sitter import Node

from vibecleaner.agents.team import select_team
from vibecleaner.behavior import behavior_holds
from vibecleaner.collector import CollectorError, collect
from vibecleaner.fix_contract import ProviderError
from vibecleaner.imports import missing_imports
from vibecleaner.mocks import production_mocks
from vibecleaner.risk import RiskTier, classify_file
from vibecleaner.deslop import (
    _DIRECTIVE,
    _LARP,
    _comment_body,
    _is_console_debug,
    _is_test_path,
    _python_debug_call,
    _python_try_pointless,
    _script_try_pointless,
    build_cross_refs,
    detect_deslop,
    detect_repo_deslop,
    _body_statements,
    _normalize_body,
    _span_lines,
    _trivial_body,
)
from vibecleaner.models import Finding, Language, SourceFile
from vibecleaner.production import production_findings, suppress
from vibecleaner.prose import _COMPILED, detect_prose_tics
from vibecleaner.ts_parse import node_text, parse_root
from vibecleaner.workflow.interface import interface_task, page_paths

_HOST_TIMEOUT_S = 180
_PROSE = frozenset({".md", ".mdx", ".rst", ".html", ".htm"})
_MARKUP = frozenset({".html", ".htm", ".css", ".scss", ".md", ".mdx"})
_LITERALS = frozenset(
    {
        "string",
        "integer",
        "float",
        "true",
        "false",
        "none",
        "list",
        "dictionary",
        "set",
        "concatenated_string",
        "number",
        "template_string",
        "array",
        "object",
        "undefined",
        "null",
    }
)
_STRINGS = re.compile(r"""(?x)(?:\"([^\"\\]{3,})\"|'([^'\\]{3,})')""")
_TOKEN = re.compile(r"[A-Za-z][A-Za-z0-9]+")
_GRADIENT = re.compile(r"background(?:-image)?\s*:[^;{}]*linear-gradient\([^;]*\)\s*;?", re.I)
_GLASS = re.compile(r"-webkit-backdrop-filter\s*:[^;]*;?|backdrop-filter\s*:[^;]*;?", re.I)
_SHADOW = re.compile(r"box-shadow\s*:[^;]*;?", re.I)
_PILL = re.compile(r"border-radius\s*:\s*(?:9999|999|50%|999px|9999px)\s*;?", re.I)
_LOREM = re.compile(r"\blorem\s+ipsum\b", re.I)
_LOREM_SENTENCE = re.compile(r"\blorem\s+ipsum\b[^.<\n]*(?:\.\s*)?", re.I)
_EMPTY_PARA = re.compile(r"<p\b[^>]*>\s*</p>\s*", re.I)
_EMOJI = re.compile(r"[\U0001F300-\U0001FAFF]\uFE0F?")
_TRAP = re.compile(
    r"""\s+onkeydown\s*=\s*(?P<q>["'])[^"']*Tab[^"']*preventDefault[^"']*(?P=q)""",
    re.I,
)
_HEAD = re.compile(r"<head\b[^>]*>", re.I)
_PARA = re.compile(r"<p\b[^>]*>(.*?)</p>", re.I | re.S)
_TAG = re.compile(r"<[^>]+>")
_FENCE = re.compile(r"```.*?```", re.S)
_VIEWPORT = '<meta name="viewport" content="width=device-width, initial-scale=1">'
_CODE_SUFFIXES = frozenset(
    {
        ".c",
        ".cc",
        ".cpp",
        ".cs",
        ".dart",
        ".ex",
        ".exs",
        ".go",
        ".graphql",
        ".h",
        ".hpp",
        ".java",
        ".js",
        ".jsx",
        ".kt",
        ".kts",
        ".lua",
        ".m",
        ".mjs",
        ".mm",
        ".php",
        ".py",
        ".pyi",
        ".rb",
        ".rs",
        ".scala",
        ".sql",
        ".svelte",
        ".swift",
        ".ts",
        ".tsx",
        ".vue",
    }
)
_VENDOR_PARTS = frozenset(
    {
        "vendor",
        "third_party",
        "third-party",
        "thirdparty",
        "Pods",
        "Carthage",
        "bower_components",
        "jspm_packages",
        "Godeps",
        ".bundle",
    }
)
_DEBUG_LINE = re.compile(
    r"^(?:debugger;?|breakpoint\(\)|binding\.pry|byebug"
    r"|import\s+pdb|import\s+ipdb|from\s+pdb\s+import\s+\S+"
    r"|console\.(?:log|debug)\(.*\);?"
    r"|pdb\.set_trace\(\)|ipdb\.set_trace\(\)"
    r"|binding\.irb|byebug"
    r"|dbg!\(.*\))$"
)


@dataclass(frozen=True)
class FixReport:
    changed: tuple[str, ...]
    remaining: tuple[str, ...]
    host: str
    workers: int
    held: tuple[str, ...] = ()

    @property
    def clean(self) -> bool:
        return not self.remaining and not self.held


def fix_tree(root: Path, *, use_host: bool = True, skip_rules: frozenset[str] = frozenset()) -> FixReport:
    """Clean ``root`` and return what changed and what is still residue."""
    root = Path(root).expanduser().resolve()
    if not root.is_dir():
        raise CollectorError(f"{root} is not a directory")
    ctx = collect(root)
    workers = _worker_count(len(ctx.files))
    facts = _fact_words(ctx.files)
    changed, held, origins = _write_pass(ctx.files, facts, workers, skip_rules)
    # A deletion can uncover another proven edit. Stop when a pass writes nothing.
    for _ in range(3):
        if not changed:
            break
        again = collect(root)
        facts = _fact_words(again.files)
        batch, more_held, more_origins = _write_pass(again.files, facts, workers, skip_rules)
        held.extend(item for item in more_held if item not in held)
        origins.update(more_origins)
        if not batch:
            break
        changed.extend(path for path in batch if path not in changed)
    changed, origins = _merge_structure(root, changed, origins, skip_rules)
    host = _host_pass(root, use_host=use_host)
    if host == "ran":
        again = collect(root)
        facts = _fact_words(again.files)
        batch, more_held, more_origins = _write_pass(again.files, facts, workers, skip_rules)
        held.extend(item for item in more_held if item not in held)
        origins.update(more_origins)
        for path in batch:
            if path not in changed:
                changed.append(path)
        changed, origins = _merge_structure(root, changed, origins, skip_rules)
    final = collect(root)
    remaining = _remaining(root, final.files, workers)
    if changed and not skip_rules:
        _record_checkpoint(root, origins)
    return FixReport(
        changed=tuple(changed),
        remaining=remaining,
        host=host,
        workers=workers,
        held=tuple(held),
    )


def revert_rule(root: Path, rule: str) -> tuple[str, ...]:
    """Restore files a rule changed, then re-apply every other rule."""
    root = Path(root).expanduser().resolve()
    path = root / ".vibecleaner" / "checkpoint.json"
    if not path.is_file():
        raise CollectorError(f"no checkpoint at {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    restored: list[str] = []
    for file, rules in list(data.get("rules", {}).items()):
        if rule not in rules:
            continue
        destination = root / file
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(data["original"][file], encoding="utf-8")
        data["rules"][file] = [item for item in rules if item != rule]
        restored.append(file)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    if restored:
        fix_tree(root, use_host=False, skip_rules=frozenset({rule}))
    return tuple(restored)


def _merge_structure(
    root: Path,
    changed: list[str],
    origins: dict[str, tuple[str, tuple[str, ...]]],
    skip_rules: frozenset[str],
) -> tuple[list[str], dict[str, tuple[str, tuple[str, ...]]]]:
    from vibecleaner.structure import repair_structure

    for path, (original, rules) in repair_structure(root, skip_rules).items():
        if path not in changed:
            changed.append(path)
        if path in origins:
            previous, previous_rules = origins[path]
            origins[path] = (previous, tuple(dict.fromkeys((*previous_rules, *rules))))
        else:
            origins[path] = (original, rules)
    return changed, origins


def _record_checkpoint(root: Path, origins: dict[str, tuple[str, tuple[str, ...]]]) -> None:
    directory = root / ".vibecleaner"
    directory.mkdir(exist_ok=True)
    path = directory / "checkpoint.json"
    if path.is_file():
        data = json.loads(path.read_text(encoding="utf-8"))
    else:
        data = {"original": {}, "rules": {}}
    for file, (original, rules) in origins.items():
        data["original"].setdefault(file, original)
        stored = data["rules"].setdefault(file, [])
        for rule in rules:
            if rule not in stored:
                stored.append(rule)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    origin = {}
    for file, rules in data["rules"].items():
        if not rules:
            continue
        current = (root / file).read_text(encoding="utf-8") if (root / file).is_file() else ""
        lines = _changed_line_numbers(data["original"].get(file, ""), current)
        origin[file] = [
            {"line": line, "rules": list(rules), "source": "autofix"} for line in lines
        ]
        origin[file].append({"line": 0, "rules": [], "source": "preexisting"})
    (directory / "origin.json").write_text(json.dumps(origin, indent=2) + "\n", encoding="utf-8")


def _changed_line_numbers(before: str, after: str) -> list[int]:
    import difflib

    matcher = difflib.SequenceMatcher(a=before.splitlines(), b=after.splitlines())
    numbers: list[int] = []
    for tag, _i1, _i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            continue
        numbers.extend(range(j1 + 1, max(j2, j1) + 1))
    return numbers


def _worker_count(file_count: int) -> int:
    """How many files to clean at once. One file stays on this thread."""
    if file_count <= 1:
        return 1
    cores = os.cpu_count() or 2
    return max(2, min(8, cores, file_count))


def _write_pass(
    files: list[SourceFile], facts: set[str], workers: int, skip_rules: frozenset[str]
) -> tuple[list[str], list[str], dict[str, tuple[str, tuple[str, ...]]]]:
    """Clean each file on its own thread, then write the results in path order.

    A high-risk file is not written. A Python edit that returns a different
    value on the same inputs is not written.
    """
    jobs = [source for source in files if _in_scope(source.path)]
    if not jobs:
        return [], [], {}

    def run(source: SourceFile) -> tuple[str, str, str, tuple[str, ...]] | None:
        updated, rules = _clean_text(source, facts, skip_rules)
        if updated == source.text:
            return None
        if classify_file(source.path, source.text) is RiskTier.HIGH:
            return ("held", source.path, f"{source.path} is high-risk and was left for a person", ())
        if source.language == Language.PYTHON and not behavior_holds(source.text, updated):
            return ("held", source.path, f"{source.path} edit reverted because the results differ", ())
        if _lost_signal(source.text, updated):
            return ("held", source.path, f"{source.path} edit reverted because a log or correlation id disappeared", ())
        return ("edit", source.path, updated, tuple(sorted(rules)))

    if workers == 1:
        results = [run(source) for source in jobs]
    else:
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="vibecleaner") as pool:
            results = list(pool.map(run, jobs))
    changed: list[str] = []
    held: list[str] = []
    origins: dict[str, tuple[str, tuple[str, ...]]] = {}
    by_path = {source.path: source for source in jobs}
    for item in results:
        if item is None:
            continue
        kind, path, payload, rules = item
        if kind == "held":
            held.append(payload)
            continue
        origins[path] = (by_path[path].text, rules)
        by_path[path].abs_path.write_text(payload, encoding="utf-8", newline="\n")
        changed.append(path)
    return changed, held, origins


def _lost_signal(before: str, after: str) -> bool:
    needles = ("correlation_id", "trace_id", "logger.", "logging.", "sentry.")
    return any(needle in before and needle not in after for needle in needles)


def _in_scope(path: str) -> bool:
    if _is_test_path(path) or _is_vendor(path):
        return False
    return True


def _is_vendor(path: str) -> bool:
    return any(part in _VENDOR_PARTS for part in PurePosixPath(path).parts)


def _clean_text(source: SourceFile, facts: set[str], skip_rules: frozenset[str]) -> tuple[str, set[str]]:
    text, rules = _clean_code(source, skip_rules)
    suffix = PurePosixPath(source.path).suffix.lower()
    if suffix in _CODE_SUFFIXES:
        text, line_rules = _clean_lines(text, skip_rules)
        rules.update(line_rules)
    if suffix in {".vue", ".svelte"}:
        suffix_for_surface = ".html"
    else:
        suffix_for_surface = suffix
    if suffix_for_surface not in _MARKUP and suffix_for_surface not in _PROSE:
        return text, rules
    if "surface.chrome" in skip_rules:
        return text, rules
    surface = _clean_surface(text, source.path if suffix_for_surface == suffix else "page.html", facts)
    if surface != text:
        rules.add("surface.chrome")
    return surface, rules


def _clean_lines(text: str, skip_rules: frozenset[str]) -> tuple[str, set[str]]:
    """Drop a full-line debug statement or narrating comment in any language."""
    kept: list[str] = []
    rules: set[str] = set()
    for line in text.splitlines(keepends=True):
        body = line.strip()
        comment = _line_comment(body)
        if (
            "D9.larp_comment" not in skip_rules
            and comment is not None
            and not _DIRECTIVE.search(comment)
            and _LARP.search(comment)
        ):
            rules.add("D9.larp_comment")
            continue
        if "D9.debug_leftover" not in skip_rules and _DEBUG_LINE.match(body):
            rules.add("D9.debug_leftover")
            continue
        kept.append(line)
    return "".join(kept), rules


def _line_comment(stripped: str) -> str | None:
    if stripped.startswith("//"):
        return stripped[2:].strip()
    if stripped.startswith("#") and not stripped.startswith("#!"):
        return stripped[1:].strip()
    if stripped.startswith("-- ") or stripped.startswith("--\t"):
        return stripped[2:].strip()
    if stripped.startswith("/*") and stripped.endswith("*/"):
        return stripped[2:-2].strip().strip("*").strip()
    return None


def _clean_code(source: SourceFile, skip_rules: frozenset[str]) -> tuple[str, set[str]]:
    if source.language not in {Language.PYTHON, Language.TYPESCRIPT, Language.TSX, Language.JAVASCRIPT}:
        return source.text, set()
    root = parse_root(source)
    if root is None or root.has_error:
        return source.text, set()
    raw = source.text.encode("utf-8")
    spans = [span for span in _code_spans(source, root, raw) if span[3] not in skip_rules]
    if not spans:
        return source.text, set()
    updated = _apply(raw, spans).decode("utf-8")
    if not _parses(source, updated):
        return source.text, set()
    return updated, {span[3] for span in spans}


def _code_spans(source: SourceFile, root: Node, raw: bytes) -> list[tuple[int, int, bytes]]:
    spans: list[tuple[int, int, bytes]] = []
    unused = {
        (finding.line, finding.symbol)
        for finding in detect_deslop(source)
        if finding.rule_id == "D9.unused_private" and finding.symbol
    }
    for node in _walk(root):
        if _is_unused(node, unused):
            spans.append(_line_span(raw, node.start_byte, node.end_byte, "D9.unused_private"))
            continue
        if node.type == "comment" and _larp(node):
            spans.append(_comment_span(raw, node, "D9.larp_comment"))
            continue
        if _debug_statement(source, node):
            spans.append(_line_span(raw, node.start_byte, node.end_byte, "D9.debug_leftover"))
            continue
        if node.type == "try_statement" and _pointless(source, node):
            spans.append((*_unwrap(raw, node), "D9.pointless_catch"))
            continue
        replacement = _stub_replacement(source, root, node, raw, unused)
        if replacement is not None:
            spans.append(replacement)
    spans.extend(_duplicate_calls(source, root, raw))
    return _without_overlap(spans)


def _duplicate_calls(source: SourceFile, root: Node, raw: bytes) -> list[tuple[int, int, bytes]]:
    """Turn a later copy of a module-level body into a call to the first."""
    language = source.language
    groups: dict[tuple[str, ...], list[tuple[Node, list[str], str]]] = {}
    parent_type = "module" if language == Language.PYTHON else "program"
    for node in _walk(root):
        if node.type not in {"function_definition", "function_declaration"}:
            continue
        if node.parent is None or node.parent.type != parent_type:
            continue
        name_node = node.child_by_field_name("name")
        body = next((child for child in node.named_children if child.type in {"block", "statement_block"}), None)
        if name_node is None or body is None:
            continue
        params = _param_list(node)
        statements = _body_statements(body, language)
        if _trivial_body(statements) or _span_lines(statements) < 8:
            continue
        key = _normalize_body(body, language)
        if not key:
            continue
        groups.setdefault(key, []).append((node, params, node_text(name_node)))
    spans: list[tuple[int, int, bytes]] = []
    for copies in groups.values():
        if len(copies) < 2:
            continue
        _node, _params, original = copies[0]
        for node, params, name in copies[1:]:
            if name == original or len(params) != len(_params):
                continue
            body = next(child for child in node.named_children if child.type in {"block", "statement_block"})
            call = f"{original}({', '.join(params)})"
            payload = f"return {call}" if language == Language.PYTHON else f"return {call};"
            indent = node.start_byte - _line_start(raw, node.start_byte)
            line = b" " * (indent + 4) + payload.encode()
            start = body.start_byte if body.type == "statement_block" else _line_start(raw, body.start_byte)
            spans.append((start, body.end_byte, _stub_body(body, line, raw), "D9.duplicate_function"))
    return spans


def _walk(node: Node):
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(reversed(current.children))


def _is_unused(node: Node, unused: set[tuple[int, str]]) -> bool:
    if node.type not in {"function_definition", "class_definition"}:
        return False
    name = node.child_by_field_name("name")
    if name is None:
        return False
    return (node.start_point[0] + 1, node_text(name)) in unused


def _larp(node: Node) -> bool:
    body = _comment_body(node_text(node))
    if not body or body.startswith("!") or _DIRECTIVE.search(body):
        return False
    return _LARP.search(body) is not None


def _debug_statement(source: SourceFile, node: Node) -> bool:
    if source.language == Language.PYTHON:
        if node.type == "expression_statement":
            call = next((child for child in node.named_children if child.type == "call"), None)
            return call is not None and _python_debug_call(call) and len(node.named_children) == 1
        if node.type in {"import_statement", "import_from_statement"}:
            text = node_text(node)
            return bool(re.fullmatch(r"import\s+(?:pdb|ipdb)\b", text.strip())) or text.strip().startswith(
                "from pdb "
            ) or text.strip().startswith("from ipdb ")
        return False
    if node.type == "debugger_statement":
        return True
    if node.type == "expression_statement":
        call = next((child for child in node.named_children if child.type == "call_expression"), None)
        return call is not None and _is_console_debug(call)
    return False


def _pointless(source: SourceFile, node: Node) -> bool:
    if source.language == Language.PYTHON:
        return _python_try_pointless(node)
    return _script_try_pointless(node)


def _unwrap(raw: bytes, node: Node) -> tuple[int, int, bytes]:
    block_type = "block" if any(child.type == "block" for child in node.named_children) else "statement_block"
    block = next(child for child in node.named_children if child.type == block_type)
    start = _line_start(raw, node.start_byte)
    indent = node.start_byte - start
    lines: list[bytes] = []
    children = block.named_children
    if block_type == "statement_block":
        children = [child for child in children if child.type not in {"{"}]
    for child in children:
        for line in raw[child.start_byte : child.end_byte].splitlines():
            lines.append(b" " * indent + line)
    return start, node.end_byte, b"\n".join(lines)


def _stub_replacement(
    source: SourceFile,
    root: Node,
    node: Node,
    raw: bytes,
    unused: set[tuple[int, str]],
) -> tuple[int, int, bytes] | None:
    if node.type not in {"function_definition", "function_declaration"}:
        return None
    params = _param_list(node)
    if not params:
        return None
    body = next((child for child in node.named_children if child.type in {"block", "statement_block"}), None)
    if body is None or _names_used(body, set(params)):
        return None
    statements = [
        child
        for child in body.named_children
        if child.type not in {"comment", "{", "}"}
    ]
    if not statements or not all(_stub_statement(child) for child in statements):
        return None
    if not any(child.type in {"return_statement"} for child in statements):
        return None
    name = node.child_by_field_name("name")
    label = node_text(name) if name is not None else "function"
    start = _line_start(raw, body.start_byte)
    indent = node.start_byte - _line_start(raw, node.start_byte)
    pad = b" " * (indent + 4)
    sibling = _sibling(root, node, params, unused)
    if sibling is not None:
        call = f"{sibling}({', '.join(params)})"
        payload = f"return {call}" if source.language == Language.PYTHON else f"return {call};"
    elif source.language == Language.PYTHON:
        payload = f'raise RuntimeError("stub: {label} ignores its input")'
    else:
        payload = f'throw new Error("stub: {label} ignores its input");'
    line = pad + payload.encode()
    return (
        body.start_byte if body.type == "statement_block" else start,
        body.end_byte,
        _stub_body(body, line, raw),
        "D6b.hardcoded_mock_stub",
    )


def _sibling(root: Node, node: Node, params: list[str], unused: set[tuple[int, str]]) -> str | None:
    """The one other function that already uses these parameters."""
    found: list[str] = []
    for other in _walk(root):
        if other is node or other.type != node.type:
            continue
        name_node = other.child_by_field_name("name")
        if name_node is None:
            continue
        name = node_text(name_node)
        if (other.start_point[0] + 1, name) in unused:
            continue
        if _param_list(other) != params:
            continue
        body = next((child for child in other.named_children if child.type in {"block", "statement_block"}), None)
        if body is None or not _names_used(body, set(params)):
            continue
        found.append(name)
    if len(found) != 1:
        return None
    return found[0]


def _stub_body(body: Node, line: bytes, raw: bytes) -> bytes:
    if body.type != "statement_block":
        return line
    text = raw[body.start_byte : body.end_byte]
    open_brace = text.find(b"{")
    close = text.rfind(b"}")
    if open_brace < 0 or close < 0:
        return line
    return text[: open_brace + 1] + b"\n" + line + b"\n" + text[close:]


def _stub_statement(node: Node) -> bool:
    if node.type == "expression_statement" and len(node.named_children) == 1:
        return node.named_children[0].type in {"string", "template_string"}
    if node.type != "return_statement":
        return False
    named = [child for child in node.named_children if child.type != "comment"]
    return bool(named) and all(_literal_node(child) for child in named)


def _literal_node(node: Node) -> bool:
    if node.type in {"none", "false", "null", "undefined"}:
        return False
    if node.type in {"string", "integer", "float", "true", "number", "concatenated_string"}:
        return True
    if node.type == "pair":
        return all(_literal_node(child) for child in node.named_children)
    if node.type in {"list", "dictionary", "set", "array", "object", "template_string"}:
        return all(_literal_node(child) for child in node.named_children)
    return False


def _param_list(node: Node) -> list[str]:
    params = node.child_by_field_name("parameters")
    if params is None:
        return []
    names: list[str] = []
    for child in params.named_children:
        if child.type == "identifier":
            name = node_text(child)
        else:
            named = child.child_by_field_name("name")
            if named is None:
                named = next((item for item in child.children if item.type == "identifier"), None)
            name = node_text(named) if named is not None else ""
        if name and name not in {"self", "cls"}:
            names.append(name)
    return names


def _names_used(body: Node, params: set[str]) -> bool:
    for child in _walk(body):
        if child.type == "identifier" and node_text(child) in params:
            return True
    return False


def _line_start(raw: bytes, index: int) -> int:
    return raw.rfind(b"\n", 0, index) + 1


def _line_span(raw: bytes, start: int, end: int, rule: str) -> tuple[int, int, bytes, str]:
    line_start = _line_start(raw, start)
    line_end = raw.find(b"\n", end)
    if line_end < 0:
        line_end = len(raw)
    else:
        line_end += 1
    segment = raw[line_start:line_end]
    node = raw[start:end]
    if segment.strip() == node.strip():
        return line_start, line_end, b"", rule
    return start, end, b"", rule


def _comment_span(raw: bytes, node: Node, rule: str) -> tuple[int, int, bytes, str]:
    return _line_span(raw, node.start_byte, node.end_byte, rule)


def _without_overlap(spans: list[tuple[int, int, bytes, str]]) -> list[tuple[int, int, bytes, str]]:
    ordered = sorted(spans, key=lambda item: (item[0], -(item[1] - item[0])))
    kept: list[tuple[int, int, bytes, str]] = []
    occupied = -1
    for start, end, replacement, rule in ordered:
        if start < occupied:
            continue
        kept.append((start, end, replacement, rule))
        occupied = end
    return kept


def _apply(raw: bytes, spans: list[tuple[int, int, bytes, str]]) -> bytes:
    for start, end, replacement, _rule in sorted(spans, key=lambda item: item[0], reverse=True):
        raw = raw[:start] + replacement + raw[end:]
    return raw


def _parses(source: SourceFile, text: str) -> bool:
    if source.language == Language.PYTHON:
        try:
            ast.parse(text)
        except SyntaxError:
            return False
        return True
    trial = SourceFile(source.path, source.abs_path, source.language, text)
    root = parse_root(trial)
    return root is not None and not root.has_error


def _fact_words(files: list[SourceFile]) -> set[str]:
    words: set[str] = set()
    for source in files:
        suffix = PurePosixPath(source.path).suffix.lower()
        if suffix in {".md", ".mdx", ".rst", ".html", ".htm"}:
            words.update(_tokens(_heading(source.text)))
        words.update(re.findall(r"https?://[^\s)>\"]+", source.text))
        words.update(re.findall(r"\b\d{2,}\b", source.text))
        if source.language == Language.OTHER and suffix not in {".py", ".ts", ".tsx", ".js", ".jsx"}:
            continue
        for match in _STRINGS.finditer(source.text):
            words.update(_tokens(match.group(1) or match.group(2) or ""))
    kept: set[str] = set()
    for word in words:
        folded = word.casefold()
        if folded.isdigit() or len(folded) >= 4:
            kept.add(folded)
    return kept


def _heading(text: str) -> str:
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("# "):
            return stripped[2:]
        found = re.search(r"<h1\b[^>]*>(.*?)</h1>", text, re.I | re.S)
        if found:
            return _TAG.sub(" ", found.group(1))
    return ""


def _tokens(text: str) -> set[str]:
    return set(_TOKEN.findall(text))


def _clean_surface(text: str, path: str, facts: set[str]) -> str:
    suffix = PurePosixPath(path).suffix.lower()
    if suffix in {".md", ".mdx", ".rst"}:
        text = _drop_prose(text, path, facts)
    if suffix in {".html", ".htm", ".css", ".scss"}:
        from vibecleaner.surface_rules import apply_design

        text = apply_design(text, suffix)
        text = _GRADIENT.sub("", text)
        text = _GLASS.sub("", text)
        text = re.sub(r"font-family\s*:[^;{}]*\bInter\b[^;{}]*;?", "", text, flags=re.I)
        text = re.sub(
            r"background(?:-image)?\s*:[^;{}]*(?:radial-gradient|repeating-linear-gradient)\([^;]*\)[^;]*;?",
            "",
            text,
            flags=re.I,
        )
        if len(_SHADOW.findall(text)) >= 3:
            text = _SHADOW.sub("", text)
        if len(_PILL.findall(text)) >= 3:
            text = _PILL.sub("", text)
    if suffix in {".html", ".htm"}:
        text = _TRAP.sub("", text)
        text = _EMOJI.sub("", text)
        text = _LOREM_SENTENCE.sub("", text)
        text = _EMPTY_PARA.sub("", text)
        if "viewport" not in text.lower() and _HEAD.search(text):
            text = _HEAD.sub(lambda match: match.group(0) + "\n" + _VIEWPORT, text, count=1)
        text = _PARA.sub(lambda match: _drop_paragraph(match, facts), text)
        text = _drop_cloned_buttons(text)
        text = _demote_extra_primaries(text)
    return text


def _demote_extra_primaries(text: str) -> str:
    """Keep one primary CTA button/link and demote extra primary classes."""
    seen = False

    def _replace(match: re.Match[str]) -> str:
        nonlocal seen
        tag = match.group(0)
        klass = re.search(r"""(\bclass\s*=\s*)(['"])([^'"]*)\2""", tag, re.I)
        if klass is None:
            return tag
        tokens = klass.group(3).split()
        if not any(tok.lower() in {"primary", "btn-primary"} for tok in tokens):
            return tag
        if not seen:
            seen = True
            return tag
        demoted = [
            "btn-secondary" if tok.lower() == "btn-primary" else ("secondary" if tok.lower() == "primary" else tok)
            for tok in tokens
        ]
        new_attr = f"{klass.group(1)}{klass.group(2)}{' '.join(demoted)}{klass.group(2)}"
        return tag[: klass.start()] + new_attr + tag[klass.end() :]

    return re.sub(r"<(?:button|a)\b[^>]*>", _replace, text, flags=re.I)


def _drop_cloned_buttons(text: str) -> str:
    """Keep one button when a class is repeated with no handler."""
    matches = list(re.finditer(r"<button\b([^>]*)>(.*?)</button>", text, re.I | re.S))
    groups: dict[str, list[re.Match[str]]] = {}
    for match in matches:
        attrs = match.group(1)
        if re.search(r"\bon(?:click|keydown)\b|\bform=", attrs, re.I):
            continue
        klass = re.search(r"""class\s*=\s*["']([^"']+)["']""", attrs, re.I)
        if klass is None:
            continue
        groups.setdefault(klass.group(1), []).append(match)
    drop = [match for group in groups.values() if len(group) >= 6 for match in group[1:]]
    for match in reversed(drop):
        text = text[: match.start()] + text[match.end() :]
    return text


def _drop_paragraph(match: re.Match[str], facts: set[str]) -> str:
    inner = _TAG.sub(" ", match.group(1))
    if _interchangeable(inner, facts) or (_tic(inner) and _no_fact(inner, facts)):
        return ""
    return match.group(0)


def _drop_prose(text: str, path: str, facts: set[str]) -> str:
    text = text.replace("\r\n", "\n")
    fenced = _fenced_lines(text)
    lines = text.splitlines(keepends=True)
    kept: list[str] = []
    paragraph: list[str] = []

    def flush() -> None:
        if not paragraph:
            return
        body = "".join(paragraph)
        if _interchangeable(body, facts) and not any(_fenced_lines(body)):
            paragraph.clear()
            return
        kept.extend(paragraph)
        paragraph.clear()

    for index, line in enumerate(lines, start=1):
        if index in fenced:
            flush()
            kept.append(line)
            continue
        if not line.strip():
            flush()
            kept.append(line)
            continue
        visible = line
        if _tic(visible) and _no_fact(visible, facts):
            continue
        paragraph.append(line)
    flush()
    return "".join(kept)


def _fenced_lines(text: str) -> set[int]:
    covered: set[int] = set()
    for match in _FENCE.finditer(text):
        start = text[: match.start()].count("\n") + 1
        stop = text[: match.end()].count("\n") + 1
        covered.update(range(start, stop + 1))
    return covered


def _tic(line: str) -> bool:
    for _category, pattern, _note in _COMPILED:
        if pattern.search(line):
            return True
    return False


def _no_fact(line: str, facts: set[str]) -> bool:
    if re.search(r"\d|https?://|\$", line):
        return False
    tokens = {token.casefold() for token in _tokens(line) if len(token) >= 4}
    return facts.isdisjoint(tokens)


def _interchangeable(text: str, facts: set[str]) -> bool:
    words = _TOKEN.findall(_TAG.sub(" ", text))
    if len(words) < 20:
        return False
    if re.search(r"\d|https?://|\$|`", text):
        return False
    tokens = {word.casefold() for word in words if len(word) >= 4}
    return facts.isdisjoint(tokens)


def _remaining(root: Path, files: list[SourceFile], workers: int) -> tuple[str, ...]:
    refs = build_cross_refs(files)
    corpus = "\n".join(source.text for source in files)
    jobs = [source for source in files if _in_scope(source.path)]

    def scan(source: SourceFile) -> list[str]:
        found: list[str] = []
        for finding in detect_deslop(source, corpus, refs):
            found.append(f"{finding.file}:{finding.line} {finding.rule_id} {finding.message}")
        for finding in detect_prose_tics(source):
            found.append(f"{finding.file}:{finding.line} {finding.rule_id} {finding.message}")
        found.extend(_structural(source))
        return found

    if workers == 1 or len(jobs) <= 1:
        chunks = [scan(source) for source in jobs]
    else:
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="vibecleaner") as pool:
            chunks = list(pool.map(scan, jobs))
    found = [item for chunk in chunks for item in chunk]
    for finding in detect_repo_deslop(files):
        if _is_test_path(finding.file):
            continue
        found.append(f"{finding.file}:{finding.line} {finding.rule_id} {finding.message}")
    for finding in [*production_mocks(files), *missing_imports(root, files), *production_findings(root, files)]:
        if not _in_scope(finding.file):
            continue
        found.append(f"{finding.file}:{finding.line} {finding.rule_id} {finding.message}")
    return tuple(dict.fromkeys(_keep_visible(files, found)))


def _keep_visible(files: list[SourceFile], rows: list[str]) -> list[str]:
    kept = suppress(files, [_row_finding(row) for row in rows])
    visible = {(finding.file, finding.line, finding.rule_id) for finding in kept}
    return [row for row in rows if _row_key(row) in visible]


def _row_finding(row: str) -> Finding:
    file, _, rest = row.partition(":")
    line, rule, message = rest.split(" ", 2)
    return Finding(rule_id=rule, file=file, line=int(line), message=message)


def _row_key(row: str) -> tuple[str, int, str]:
    file, _, rest = row.partition(":")
    line, rule, _message = rest.split(" ", 2)
    return file, int(line), rule


def _structural(source: SourceFile) -> list[str]:
    suffix = PurePosixPath(source.path).suffix.lower()
    hits: list[str] = []
    if suffix in {".html", ".htm"}:
        buttons = len(re.findall(r"<button\b", source.text, re.I))
        if buttons >= 6 and source.text.lower().count("<button") == buttons:
            classes = re.findall(r"<button\b[^>]*class\s*=\s*[\"']([^\"']+)[\"']", source.text, re.I)
            if len(classes) >= 6 and len(set(classes)) == 1:
                hits.append(f"{source.path}:1 surface.equal_buttons {buttons} buttons share one class")
        if "linear-gradient" in source.text:
            hits.append(f"{source.path}:1 surface.gradient a gradient is still on the page")
        if _LOREM.search(source.text):
            hits.append(f"{source.path}:1 surface.lorem placeholder text is still on the page")
    return hits


def _host_pass(root: Path, *, use_host: bool) -> str:
    if not use_host or os.environ.get("VIBECLEANER_HOST", "").strip() == "":
        return "no host"
    try:
        team = select_team(root, local=False)
    except ProviderError:
        return "no host"
    if team.host is None:
        return "no host"
    pages = page_paths(root)
    files = collect(root).files
    remaining = _remaining(root, files, _worker_count(len(files)))
    if not remaining and not pages:
        return "not needed"
    before = {source.path: source.text for source in files}
    ran = False
    for item in remaining:
        allowed = {item.split(":", 1)[0]}
        try:
            result = team.host.run_task(root, _one_task(item), timeout_s=_HOST_TIMEOUT_S)
        except (ProviderError, OSError):
            _restore_others(root, before, allowed)
            return "failed"
        ran = True
        if not result.ok:
            _restore_others(root, before, set())
            return "failed"
        _restore_others(root, before, allowed)
        before = {source.path: source.text for source in collect(root).files}
    if pages:
        _path, prompt = interface_task(pages)
        allowed_pages = set(pages) | {
            source.path
            for source in collect(root).files
            if PurePosixPath(source.path).suffix.lower() in {".css", ".scss"}
        }
        try:
            result = team.host.run_task(root, prompt, timeout_s=_HOST_TIMEOUT_S)
        except (ProviderError, OSError):
            _restore_others(root, before, set())
            return "failed"
        ran = True
        if not result.ok:
            _restore_others(root, before, set())
            return "failed"
        _restore_others(root, before, allowed_pages)
    return "ran" if ran else "not needed"


def _one_task(finding: str) -> str:
    return (
        "Fix only the finding below. Touch only that file. "
        "Keep every fact, public signature, and test. "
        "Do not add a feature, a dependency, or a file. "
        f"Finding: {finding}"
    )


def _restore_others(root: Path, before: dict[str, str], allowed: set[str]) -> None:
    """Put back every file except the allowed set."""
    current = {source.path: source for source in collect(root).files}
    for path, source in current.items():
        if path in allowed:
            if source.language == Language.PYTHON:
                try:
                    ast.parse(source.text)
                except SyntaxError:
                    if path in before:
                        source.abs_path.write_text(before[path], encoding="utf-8")
            elif source.language in {Language.TYPESCRIPT, Language.TSX, Language.JAVASCRIPT} and not _parses(
                source, source.text
            ):
                if path in before:
                    source.abs_path.write_text(before[path], encoding="utf-8")
            continue
        if path in before:
            if source.text != before[path]:
                source.abs_path.write_text(before[path], encoding="utf-8")
        else:
            source.abs_path.unlink(missing_ok=True)
    for path, text in before.items():
        if path in allowed:
            continue
        destination = root / path
        if not destination.is_file():
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(text, encoding="utf-8")
