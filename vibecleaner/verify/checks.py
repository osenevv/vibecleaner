"""Deterministic before/after comparisons for the tamper guard."""

from __future__ import annotations

import difflib
import posixpath
import re
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import PurePosixPath

from tree_sitter import Node

from vibecleaner.fix_contract import Evidence, EvidenceKind
from vibecleaner.models import Language
from vibecleaner.ts_parse import callee_name, node_text, python_string, script_string, walk_tree
from vibecleaner.verify.config_text import dig, load_ini, load_json, load_toml
from vibecleaner.verify.files import line_of, parsed
from vibecleaner.verify.signatures import (
    function_params,
    iter_functions,
    signature_changed,
    signature_index,
)
from vibecleaner.verify.snapshot import TamperSnapshot

_TRIVIAL = frozenset({"", "0", "1", "-1", "True", "False", "None", "true", "false", "null", "undefined"})
_WEAK_MATCHERS = frozenset(
    {"toBeDefined", "toBeFalsy", "toBeNaN", "toBeNull", "toBeTruthy", "toBeUndefined"}
)
_STRONG_OPS = frozenset({"==", "!=", "<", ">", "<=", ">=", "in", "not in"})
_PATCH_CALLS = frozenset(
    {
        "mock.patch",
        "mock.patch.object",
        "mocker.patch",
        "mocker.patch.object",
        "monkeypatch.setattr",
        "patch",
        "patch.object",
        "unittest.mock.patch",
        "unittest.mock.patch.object",
    }
)
_JS_MOCKS = frozenset({"jest.doMock", "jest.mock", "vi.doMock", "vi.mock"})
_SKIP_CALLS = frozenset({"pytest.skip", "pytest.xfail", "unittest.skip"})
_JS_SKIPS = frozenset(
    {
        "describe.only",
        "describe.skip",
        "fdescribe",
        "fit",
        "it.only",
        "it.skip",
        "it.todo",
        "test.only",
        "test.skip",
        "test.todo",
        "xdescribe",
        "xit",
        "xtest",
    }
)
_SKIP_LEAVES = frozenset({"skip", "skipif", "xfail"})
_IGNORE = re.compile(
    r"#\s*type:\s*ignore\b|#\s*noqa\b|eslint-disable|@ts-ignore\b|@ts-expect-error\b|@ts-nocheck\b",
    re.IGNORECASE,
)
_COV_UNDER = re.compile(r"--cov-fail-under(?:=|\s+)(\d+(?:\.\d+)?)")
_RULE_OFF = re.compile(r"""['"]([^'"]+)['"]\s*:\s*(?:['"]off['"]|0|false)\b""")
_NESTED = frozenset(
    {
        "arrow_function",
        "class_declaration",
        "class_definition",
        "decorated_definition",
        "function_declaration",
        "function_definition",
        "function_expression",
        "method_definition",
    }
)


@dataclass(frozen=True)
class _Assertion:
    line: int
    subject: str
    strong: bool


@dataclass(frozen=True)
class _Handler:
    line: int
    breadth: int
    empty: bool


@dataclass(frozen=True)
class _Lint:
    selected: frozenset[str] | None
    ignored: frozenset[str]
    disabled: frozenset[str]


def collect_findings(
    before: TamperSnapshot,
    after: TamperSnapshot,
    allowed: frozenset[str],
) -> list[Evidence]:
    found: list[Evidence] = []
    found.extend(_deleted_tests(before, after))
    found.extend(_assertions(before, after))
    found.extend(_skips(before, after))
    found.extend(_mocks(before, after))
    found.extend(_excepts(before, after))
    found.extend(_configs(before, after))
    found.extend(_ignores(before, after))
    found.extend(_hardcoded(before, after))
    found.extend(_signatures(before, after, allowed))
    return found


def _deleted_tests(before: TamperSnapshot, after: TamperSnapshot) -> list[Evidence]:
    found: list[Evidence] = []
    for rel, text in before.tests.items():
        if rel not in after.tests:
            found.append(_evidence(f"deleted test file {rel}", rel, 1, text, ""))
            continue
        after_text = after.tests[rel]
        previous = Counter(_test_names(rel, text))
        current = Counter(_test_names(rel, after_text))
        for name, count in previous.items():
            missing = count - current.get(name, 0)
            if missing <= 0:
                continue
            found.append(_evidence(f"deleted test {name}", rel, _test_line(rel, text, name), text, after_text))
    return found


def _assertions(before: TamperSnapshot, after: TamperSnapshot) -> list[Evidence]:
    found: list[Evidence] = []
    for rel, text in before.tests.items():
        if rel not in after.tests:
            continue
        after_text = after.tests[rel]
        previous = _assertions_in(rel, text)
        current = _assertions_in(rel, after_text)
        for name, old in previous.items():
            if name not in current:
                continue
            new = current[name]
            if len(new) < len(old):
                line = new[0].line if new else _test_line(rel, after_text, name)
                found.append(_evidence(f"fewer assertions in {name}", rel, line, text, after_text))
            found.extend(
                _evidence(f"weakened assertion in {name}", rel, item.line, text, after_text)
                for item in _weakened(old, new)
            )
    return found


def _skips(before: TamperSnapshot, after: TamperSnapshot) -> list[Evidence]:
    found: list[Evidence] = []
    files = set(before.tests) | set(after.tests)
    for rel in sorted(files):
        previous = Counter(_skip_keys(rel, before.tests.get(rel, "")))
        current = _skip_sites(rel, after.tests.get(rel, ""))
        for kind, line, label in current:
            key = (kind, label)
            if previous[key]:
                previous[key] -= 1
                continue
            text = after.tests.get(rel, "")
            found.append(
                _evidence(
                    f"new {kind} in {label or rel}",
                    rel,
                    line,
                    before.tests.get(rel, ""),
                    text,
                )
            )
    return found


def _mocks(before: TamperSnapshot, after: TamperSnapshot) -> list[Evidence]:
    found: list[Evidence] = []
    files = set(before.tests) | set(after.tests)
    for rel in sorted(files):
        previous = Counter(_mock_targets(rel, before.tests.get(rel, ""), after.sources))
        current = _mock_sites(rel, after.tests.get(rel, ""), after.sources)
        for target, line in current:
            if previous[target]:
                previous[target] -= 1
                continue
            found.append(
                _evidence(
                    f"mocks the module under test ({target})",
                    rel,
                    line,
                    before.tests.get(rel, ""),
                    after.tests.get(rel, ""),
                )
            )
    return found


def _excepts(before: TamperSnapshot, after: TamperSnapshot) -> list[Evidence]:
    found: list[Evidence] = []
    files = set(before.sources) | set(after.sources)
    for rel in sorted(files):
        old_text = before.sources.get(rel, "")
        new_text = after.sources.get(rel, "")
        if old_text == new_text:
            continue
        script = _is_script(rel)
        previous = _handlers(rel, old_text)
        current = _handlers(rel, new_text)
        names = set(previous) | set(current)
        for name in sorted(names):
            old = previous.get(name, [])
            new = current.get(name, [])
            for left, right in zip(old, new):
                summary = _handler_change(left, right, script)
                if summary:
                    found.append(_evidence(f"{summary} in {name}", rel, right.line, old_text, new_text))
            for handler in new[len(old) :]:
                if _new_handler_is_tamper(handler, script):
                    summary = _empty_label(handler, script)
                    found.append(_evidence(f"{summary} in {name}", rel, handler.line, old_text, new_text))
    return found


def _configs(before: TamperSnapshot, after: TamperSnapshot) -> list[Evidence]:
    found: list[Evidence] = []
    for rel, text in before.configs.items():
        updated = after.configs.get(rel)
        if updated is None:
            found.append(_evidence(f"removed config {rel}", rel, 1, text, ""))
            continue
        if updated == text:
            continue
        found.extend(_threshold_findings(rel, text, updated))
        found.extend(_lint_findings(rel, text, updated))
    return found


def _ignores(before: TamperSnapshot, after: TamperSnapshot) -> list[Evidence]:
    found: list[Evidence] = []
    files = set(before.tests) | set(after.tests) | set(before.sources) | set(after.sources)
    for rel in sorted(files):
        old = _text_of(before, rel)
        new = _text_of(after, rel)
        if old == new:
            continue
        previous = Counter(line for _number, line in _ignore_lines(old))
        for number, line in _ignore_lines(new):
            if previous[line]:
                previous[line] -= 1
                continue
            found.append(_evidence(f"added ignore {line[:80]}", rel, number, old, new))
    return found


def _hardcoded(before: TamperSnapshot, after: TamperSnapshot) -> list[Evidence]:
    test_literals = _literals(before.tests) | _literals(after.tests)
    production = _literals(before.sources)
    suspicious = test_literals - production - _TRIVIAL
    if not suspicious:
        return []
    found: list[Evidence] = []
    for rel, text in after.sources.items():
        previous = {(qual, param, literal) for qual, param, literal, _line in _branch_hits(rel, before.sources.get(rel, ""))}
        for qualname, param, literal, line in _branch_hits(rel, text):
            if (qualname, param, literal) in previous or literal not in suspicious:
                continue
            found.append(
                _evidence(
                    f"branches on test literal {literal}",
                    rel,
                    line,
                    before.sources.get(rel, ""),
                    text,
                )
            )
    return found


def _signatures(before: TamperSnapshot, after: TamperSnapshot, allowed: frozenset[str]) -> list[Evidence]:
    found: list[Evidence] = []
    for key, old in before.signatures.items():
        if key in allowed:
            continue
        rel, qualname = key.rsplit(":", 1)
        new = after.signatures.get(key)
        old_text = before.sources.get(rel, "")
        new_text = after.sources.get(rel, "")
        if new is None:
            found.append(
                _evidence(
                    f"removed public signature {qualname}",
                    rel,
                    _signature_line(rel, old_text, key),
                    old_text,
                    new_text,
                )
            )
            continue
        if signature_changed(old, new):
            found.append(
                _evidence(
                    f"changed public signature {qualname}",
                    rel,
                    _signature_line(rel, new_text, key) or _signature_line(rel, old_text, key),
                    old_text,
                    new_text,
                )
            )
    return found


def _evidence(summary: str, file: str, line: int, before: str, after: str) -> Evidence:
    diff = "".join(
        difflib.unified_diff(
            before.splitlines(keepends=True),
            after.splitlines(keepends=True),
            fromfile=f"a/{file}",
            tofile=f"b/{file}",
            n=2,
        )
    )
    snippet = _window(before, after, line)
    return Evidence(
        kind=EvidenceKind.TAMPER,
        summary=summary,
        file=file,
        line=line or 1,
        command=("git", "diff", "--no-index", "--", f"a/{file}", f"b/{file}"),
        output=diff or snippet,
        reproducer=snippet,
    )


def _test_names(rel: str, text: str) -> list[str]:
    loaded = parsed(rel, text)
    if loaded is None:
        return []
    _source, root = loaded
    if _source.language == Language.PYTHON:
        return [name for name, _line, _node in _py_tests(root)]
    return [name for name, _line, _node in _js_tests(root)]


def _test_line(rel: str, text: str, name: str) -> int:
    loaded = parsed(rel, text)
    if loaded is None:
        return 1
    _source, root = loaded
    tests = _py_tests(root) if _source.language == Language.PYTHON else _js_tests(root)
    for test_name, line, _node in tests:
        if test_name == name:
            return line
    return 1


def _assertions_in(rel: str, text: str) -> dict[str, list[_Assertion]]:
    loaded = parsed(rel, text)
    if loaded is None:
        return {}
    source, root = loaded
    tests = _py_tests(root) if source.language == Language.PYTHON else _js_tests(root)
    grouped: dict[str, list[_Assertion]] = {}
    for name, _line, node in tests:
        body = node.child_by_field_name("body")
        reader = _py_assertion if source.language == Language.PYTHON else _js_assertion
        grouped.setdefault(name, []).extend(_read_body(body, reader))
    return grouped


def _py_tests(root: Node) -> list[tuple[str, int, Node]]:
    found: list[tuple[str, int, Node]] = []
    for node in walk_tree(root):
        target = node
        if node.type == "decorated_definition":
            definition = node.child_by_field_name("definition")
            if definition is None:
                continue
            target = definition
        if target.type != "function_definition":
            continue
        name_node = target.child_by_field_name("name")
        if name_node is None or not node_text(name_node).startswith("test_"):
            continue
        found.append((node_text(name_node), line_of(target), target))
    return found


def _js_tests(root: Node) -> list[tuple[str, int, Node]]:
    found: list[tuple[str, int, Node]] = []
    for node in walk_tree(root):
        if node.type != "call_expression":
            continue
        name = callee_name(node)
        base = name.split(".", 1)[0]
        if base not in {"it", "test"} and name not in {"it", "test"}:
            continue
        arguments = node.child_by_field_name("arguments")
        callback = _callback(arguments)
        if callback is None:
            continue
        title = _first_string(arguments) or name
        found.append((title, line_of(node), callback))
    return found


def _py_assertion(node: Node) -> _Assertion | None:
    if node.type != "assert_statement":
        return None
    expr = next((child for child in node.named_children), None)
    if expr is None:
        return _Assertion(line_of(node), "", False)
    if expr.type == "comparison_operator":
        left = expr.named_children[0] if expr.named_children else expr
        op = " ".join(node_text(child) for child in expr.children if not child.is_named)
        return _Assertion(line_of(node), _norm(node_text(left)), op in _STRONG_OPS)
    return _Assertion(line_of(node), _norm(node_text(expr)), False)


def _js_assertion(node: Node) -> _Assertion | None:
    if node.type != "call_expression":
        return None
    if _chained_expect(node):
        return None
    matcher = _matcher(node)
    if matcher is not None:
        subject, name = matcher
        return _Assertion(line_of(node), _norm(subject), name not in _WEAK_MATCHERS)
    called = callee_name(node)
    if called in {"expect", "assert"}:
        return _Assertion(line_of(node), _norm(_first_arg(node)), False)
    return None


def _weakened(old: list[_Assertion], new: list[_Assertion]) -> list[_Assertion]:
    grouped = _group(new)
    used: Counter[str] = Counter()
    found: list[_Assertion] = []
    for item in old:
        if not item.strong:
            continue
        pool = grouped.get(item.subject, [])
        index = used[item.subject]
        if index >= len(pool):
            continue
        used[item.subject] += 1
        candidate = pool[index]
        if not candidate.strong:
            found.append(candidate)
    return found


def _group(items: list[_Assertion]) -> dict[str, list[_Assertion]]:
    grouped: dict[str, list[_Assertion]] = {}
    for item in items:
        grouped.setdefault(item.subject, []).append(item)
    return grouped


def _skip_keys(rel: str, text: str) -> list[tuple[str, str]]:
    return [(kind, label) for kind, _line, label in _skip_sites(rel, text)]


def _skip_sites(rel: str, text: str) -> list[tuple[str, int, str]]:
    loaded = parsed(rel, text)
    if loaded is None:
        return []
    source, root = loaded
    if source.language == Language.PYTHON:
        return _py_skips(root)
    return _js_skips(root)


def _py_skips(root: Node) -> list[tuple[str, int, str]]:
    found: list[tuple[str, int, str]] = []
    for node in walk_tree(root):
        if node.type == "decorated_definition":
            target = node.child_by_field_name("definition")
            owner = ""
            if target is not None:
                name_node = target.child_by_field_name("name")
                owner = node_text(name_node) if name_node is not None else ""
            for child in node.named_children:
                if child.type != "decorator":
                    continue
                kind = _skip_decorator(child)
                if kind:
                    found.append((kind, line_of(child), owner))
        elif node.type == "call" and callee_name(node) in _SKIP_CALLS:
            found.append((callee_name(node), line_of(node), callee_name(node)))
    return found


def _js_skips(root: Node) -> list[tuple[str, int, str]]:
    found: list[tuple[str, int, str]] = []
    for node in walk_tree(root):
        if node.type != "call_expression":
            continue
        name = callee_name(node)
        if name not in _JS_SKIPS:
            continue
        found.append((name, line_of(node), _first_string(node.child_by_field_name("arguments")) or name))
    return found


def _skip_decorator(node: Node) -> str:
    text = node_text(node).lstrip("@").split("(", 1)[0]
    leaf = text.split(".")[-1]
    if leaf in _SKIP_LEAVES or text in _SKIP_LEAVES:
        return leaf
    return ""


def _mock_targets(rel: str, text: str, sources: Mapping[str, str]) -> list[str]:
    return [target for target, _line in _mock_sites(rel, text, sources)]


def _mock_sites(rel: str, text: str, sources: Mapping[str, str]) -> list[tuple[str, int]]:
    if not text:
        return []
    loaded = parsed(rel, text)
    if loaded is None:
        return []
    source, root = loaded
    stem = _test_stem(rel)
    found: list[tuple[str, int]] = []
    for node in walk_tree(root):
        kind = "call" if source.language == Language.PYTHON else "call_expression"
        if node.type != kind:
            continue
        name = callee_name(node)
        target = _call_target(node)
        if target is None:
            continue
        if source.language == Language.PYTHON and name in _PATCH_CALLS and _matches_module(target, stem, sources):
            found.append((target, line_of(node)))
        elif source.language != Language.PYTHON and name in _JS_MOCKS and _hits_spec(rel, target, stem, sources):
            found.append((target, line_of(node)))
    return found


def _handlers(rel: str, text: str) -> dict[str, list[_Handler]]:
    loaded = parsed(rel, text)
    if loaded is None:
        return {}
    source, root = loaded
    grouped: dict[str, list[_Handler]] = {}
    for qualname, func in iter_functions(root):
        grouped.setdefault(qualname, []).extend(_handlers_in(func, source.language == Language.PYTHON))
    return grouped


def _handlers_in(func: Node, python: bool) -> list[_Handler]:
    body = func.child_by_field_name("body")
    if body is None:
        return []
    found: list[_Handler] = []
    for node in _owned(body):
        if python and node.type == "try_statement":
            found.extend(_py_handlers(node))
        elif not python and node.type == "try_statement":
            found.extend(_js_handlers(node))
    return found


def _py_handlers(node: Node) -> list[_Handler]:
    found: list[_Handler] = []
    for child in node.named_children:
        if child.type != "except_clause":
            continue
        types = _except_types(child)
        block = next((part for part in child.named_children if part.type == "block"), None)
        found.append(_Handler(line_of(child), _breadth(types), block is None or _block_empty(block)))
    return found


def _js_handlers(node: Node) -> list[_Handler]:
    found: list[_Handler] = []
    for child in node.named_children:
        if child.type != "catch_clause":
            continue
        block = next((part for part in child.named_children if part.type == "statement_block"), None)
        empty = block is None or not any(part.type != "comment" for part in block.named_children)
        found.append(_Handler(line_of(child), 2, empty))
    return found


def _except_types(clause: Node) -> frozenset[str] | None:
    type_node = None
    for child in clause.named_children:
        if child.type == "block":
            break
        type_node = child
    if type_node is None:
        return None
    if type_node.type == "as_pattern" and type_node.named_children:
        type_node = type_node.named_children[0]
    return frozenset(_type_names(type_node))


def _type_names(node: Node) -> list[str]:
    if node.type in {"identifier", "attribute"}:
        return [node_text(node).split(".")[-1]]
    if node.type in {"tuple", "list"}:
        names: list[str] = []
        for child in node.named_children:
            names.extend(_type_names(child))
        return names
    return []


def _breadth(types: frozenset[str] | None) -> int:
    if types is None or "BaseException" in types:
        return 2
    if "Exception" in types:
        return 1
    return 0


def _block_empty(block: Node) -> bool:
    return not any(child.type not in {"comment", "pass_statement"} for child in block.named_children)


def _handler_change(old: _Handler, new: _Handler, script: bool) -> str:
    if script and new.empty and not old.empty:
        return "empty catch"
    if new.breadth > old.breadth:
        return "broadened except"
    return ""


def _empty_label(handler: _Handler, script: bool) -> str:
    if script and handler.empty:
        return "empty catch"
    if handler.empty:
        return "empty except"
    return "broadened except"


def _new_handler_is_tamper(handler: _Handler, script: bool) -> bool:
    if script:
        return handler.empty
    return handler.breadth >= 1


def _threshold_findings(rel: str, before: str, after: str) -> list[Evidence]:
    found: list[Evidence] = []
    old = _thresholds(rel, before)
    new = _thresholds(rel, after)
    for key, value in old.items():
        if key not in new:
            found.append(_evidence(f"removed {key}", rel, _line_with(after, key.split(".")[-1]), before, after))
        elif new[key] < value:
            found.append(
                _evidence(
                    f"lowered {key} from {value:g} to {new[key]:g}",
                    rel,
                    _line_with(after, key.split(".")[-1]),
                    before,
                    after,
                )
            )
    return found


def _lint_findings(rel: str, before: str, after: str) -> list[Evidence]:
    old = _lint(rel, before)
    new = _lint(rel, after)
    found: list[Evidence] = []
    if old.selected:
        if new.selected is None:
            found.append(_evidence("removed lint selection", rel, _line_with(before, "select"), before, after))
        else:
            for code in sorted(old.selected - new.selected):
                found.append(_evidence(f"removed lint rule {code}", rel, _line_with(before, code), before, after))
    for code in sorted(new.ignored - old.ignored):
        found.append(_evidence(f"ignored lint rule {code}", rel, _line_with(after, code), before, after))
    for code in sorted(new.disabled - old.disabled):
        found.append(_evidence(f"removed lint rule {code}", rel, _line_with(after, code), before, after))
    return found


def _thresholds(rel: str, text: str) -> dict[str, float]:
    name = PurePosixPath(rel).name
    found: dict[str, float] = {}
    if name == "pyproject.toml":
        data = load_toml(text)
        _put_number(found, "coverage.fail_under", dig(data, "tool", "coverage", "report", "fail_under"))
        _put_bool(found, "mypy.strict", dig(data, "tool", "mypy", "strict"))
        _put_cov_addopts(found, dig(data, "tool", "pytest", "ini_options", "addopts"))
    elif name == "package.json":
        data = load_json(text)
        jest = data.get("jest")
        if isinstance(jest, dict):
            _walk_numbers(found, "coverageThreshold", jest.get("coverageThreshold"))
    elif name.startswith("tsconfig"):
        data = load_json(text)
        compiler = data.get("compilerOptions")
        if isinstance(compiler, dict):
            _put_bool(found, "tsconfig.strict", compiler.get("strict"))
    elif name in {"setup.cfg", ".coveragerc", "tox.ini", "mypy.ini"}:
        parser = load_ini(text)
        for section in ("coverage:report", "report"):
            if parser.has_option(section, "fail_under"):
                _put_number(found, "coverage.fail_under", parser.get(section, "fail_under"))
        if parser.has_option("mypy", "strict"):
            _put_bool(found, "mypy.strict", _ini_bool(parser.get("mypy", "strict")))
        if parser.has_section("tool:pytest") and parser.has_option("tool:pytest", "addopts"):
            _put_cov_addopts(found, parser.get("tool:pytest", "addopts"))
    return found


def _lint(rel: str, text: str) -> _Lint:
    name = PurePosixPath(rel).name
    if name in {"pyproject.toml", "ruff.toml", ".ruff.toml"}:
        data = load_toml(text)
        lint = dig(data, "tool", "ruff", "lint") if name == "pyproject.toml" else data.get("lint")
        top = dig(data, "tool", "ruff") if name == "pyproject.toml" else data
        return _Lint(
            _optional_codes(_pick(lint, "select"), _pick(top, "select")),
            _codes(_pick(lint, "ignore"), _pick(lint, "extend-ignore"), _pick(top, "ignore")),
            frozenset(),
        )
    if name == "package.json":
        data = load_json(text)
        eslint = data.get("eslintConfig")
        rules = eslint.get("rules") if isinstance(eslint, dict) else None
        return _Lint(None, frozenset(), _off_rules(rules))
    if "eslint" in name and name.endswith(".json"):
        rules = load_json(text).get("rules")
        return _Lint(None, frozenset(), _off_rules(rules))
    if name.startswith("eslint.config.") or name.startswith(".eslintrc."):
        return _Lint(None, frozenset(), frozenset(_RULE_OFF.findall(text)))
    return _Lint(None, frozenset(), frozenset())


def _literals(files: Mapping[str, str]) -> set[str]:
    found: set[str] = set()
    for rel, text in files.items():
        loaded = parsed(rel, text)
        if loaded is None:
            continue
        _source, root = loaded
        for node in walk_tree(root):
            value = _literal(node)
            if value is not None:
                found.add(value)
    return found


def _branch_hits(rel: str, text: str) -> list[tuple[str, str, str, int]]:
    loaded = parsed(rel, text)
    if loaded is None:
        return []
    _source, root = loaded
    found: list[tuple[str, str, str, int]] = []
    for qualname, func in iter_functions(root):
        params = function_params(func)
        for node in _owned(func):
            condition = _branch_condition(node)
            if condition is None:
                continue
            for param, literal, line in _equalities(condition, params):
                found.append((qualname, param, literal, line))
    return found


def _owned(node: Node):
    for child in node.named_children:
        if child.type in _NESTED:
            continue
        yield child
        yield from _owned(child)


def _read_body(node: Node | None, reader):
    if node is None:
        return []
    found = []
    direct = reader(node)
    if direct is not None:
        found.append(direct)
    for child in _owned(node):
        item = reader(child)
        if item is not None:
            found.append(item)
    return found


def _branch_condition(node: Node) -> Node | None:
    if node.type in {"if_statement", "elif_clause"}:
        return node.child_by_field_name("condition")
    if node.type in {"conditional_expression", "ternary_expression"}:
        return node
    return None


def _equalities(node: Node, params: set[str]) -> list[tuple[str, str, int]]:
    found: list[tuple[str, str, int]] = []
    for current in walk_tree(node):
        if current.type == "comparison_operator":
            found.extend(_python_equality(current, params))
        elif current.type == "binary_expression":
            hit = _script_equality(current, params)
            if hit is not None:
                found.append(hit)
    return found


def _python_equality(node: Node, params: set[str]) -> list[tuple[str, str, int]]:
    sequence: list[tuple[str, object]] = []
    for child in node.children:
        if child.is_named:
            sequence.append(("val", _unwrap(child)))
        else:
            sequence.append(("op", node_text(child)))
    found: list[tuple[str, str, int]] = []
    for index, (kind, value) in enumerate(sequence):
        if kind != "op" or value not in {"==", "!="}:
            continue
        if index == 0 or index + 1 >= len(sequence):
            continue
        left = sequence[index - 1][1]
        right = sequence[index + 1][1]
        if not isinstance(left, Node) or not isinstance(right, Node):
            continue
        hit = _name_and_literal(left, right)
        if hit is None or hit[0] not in params:
            continue
        found.append((hit[0], hit[1], line_of(node)))
    return found


def _script_equality(node: Node, params: set[str]) -> tuple[str, str, int] | None:
    operator = node.child_by_field_name("operator")
    if operator is None or node_text(operator) not in {"==", "!=", "===", "!=="}:
        return None
    left = node.child_by_field_name("left")
    right = node.child_by_field_name("right")
    if left is None or right is None:
        return None
    hit = _name_and_literal(_unwrap(left), _unwrap(right))
    if hit is None or hit[0] not in params:
        return None
    return hit[0], hit[1], line_of(node)


def _name_and_literal(left: Node, right: Node) -> tuple[str, str] | None:
    if left.type == "identifier":
        literal = _literal(right)
        if literal is not None:
            return node_text(left), literal
    if right.type == "identifier":
        literal = _literal(left)
        if literal is not None:
            return node_text(right), literal
    return None


def _literal(node: Node) -> str | None:
    node = _unwrap(node)
    if node.type in {"integer", "float", "number"}:
        return node_text(node)
    if node.type == "unary_operator":
        text = node_text(node).replace(" ", "")
        if re.fullmatch(r"-?\d+(?:\.\d+)?", text):
            return text
        return None
    if node.type == "string":
        value = python_string(node)
        return script_string(node) if value is None else value
    if node.type in {"true", "false", "none", "null", "undefined"}:
        return node_text(node)
    return None


def _matches_module(target: str, stem: str, sources: Mapping[str, str]) -> bool:
    names = _module_names(stem, sources)
    if target in names:
        return True
    parts = target.split(".")
    return any(".".join(parts[:end]) in names for end in range(len(parts), 0, -1))


def _hits_spec(test_rel: str, spec: str, stem: str, sources: Mapping[str, str]) -> bool:
    if not spec.startswith("."):
        return _matches_module(spec.replace("/", "."), stem, sources)
    resolved = posixpath.normpath(posixpath.join(str(PurePosixPath(test_rel).parent), spec))
    names = _module_names(stem, sources)
    for ext in ("", ".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"):
        candidate = f"{resolved}{ext}"
        if candidate in sources and (PurePosixPath(candidate).stem == stem or _dotted(candidate) in names):
            return True
    return False


def _module_names(stem: str, sources: Mapping[str, str]) -> set[str]:
    names = {stem}
    for rel in sources:
        if PurePosixPath(rel).stem == stem:
            names.add(_dotted(rel))
    return names


def _test_stem(rel: str) -> str:
    path = PurePosixPath(rel)
    name = path.name
    for suffix in (
        ".spec.js",
        ".spec.jsx",
        ".spec.mjs",
        ".spec.ts",
        ".spec.tsx",
        ".test.js",
        ".test.jsx",
        ".test.mjs",
        ".test.ts",
        ".test.tsx",
    ):
        if name.endswith(suffix):
            return name[: -len(suffix)]
    stem = path.stem
    if stem.startswith("test_"):
        return stem[5:]
    if stem.endswith("_test"):
        return stem[:-5]
    return stem


def _dotted(rel: str) -> str:
    parts = list(PurePosixPath(rel).with_suffix("").parts)
    if parts and parts[0] in {"src", "lib"}:
        parts = parts[1:]
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _call_target(node: Node) -> str | None:
    arguments = node.child_by_field_name("arguments")
    if arguments is None or not arguments.named_children:
        return None
    first = arguments.named_children[0]
    if first.type == "string":
        return python_string(first) or script_string(first)
    if first.type == "identifier":
        return node_text(first)
    return None


def _callback(arguments: Node | None) -> Node | None:
    if arguments is None:
        return None
    for child in arguments.named_children:
        if child.type in {"arrow_function", "function_expression", "function"}:
            return child
    return None


def _first_string(arguments: Node | None) -> str:
    if arguments is None:
        return ""
    for child in arguments.named_children:
        if child.type == "string":
            value = python_string(child)
            return script_string(child) if value is None else value or ""
    return ""


def _first_arg(node: Node) -> str:
    arguments = node.child_by_field_name("arguments")
    if arguments is None or not arguments.named_children:
        return ""
    return node_text(arguments.named_children[0])


def _matcher(node: Node) -> tuple[str, str] | None:
    func = node.child_by_field_name("function")
    if func is None or func.type != "member_expression":
        return None
    obj = func.child_by_field_name("object")
    prop = func.child_by_field_name("property")
    if obj is None or prop is None or obj.type != "call_expression":
        return None
    if callee_name(obj) not in {"expect", "assert"}:
        return None
    return _first_arg(obj), node_text(prop)


def _chained_expect(node: Node) -> bool:
    parent = node.parent
    if parent is None or parent.type != "member_expression":
        return False
    return parent.child_by_field_name("object") == node


def _ignore_lines(text: str) -> list[tuple[int, str]]:
    return [(index, line.strip()) for index, line in enumerate(text.splitlines(), 1) if _IGNORE.search(line)]


def _text_of(snap: TamperSnapshot, rel: str) -> str:
    if rel in snap.tests:
        return snap.tests[rel]
    return snap.sources.get(rel, "")


def _signature_line(rel: str, text: str, key: str) -> int:
    if not text:
        return 1
    located = signature_index(rel, text).get(key)
    if located is None:
        return 1
    return located[1]


def _is_script(rel: str) -> bool:
    return PurePosixPath(rel).suffix.lower() not in {".py", ".pyi"}


def _put_number(found: dict[str, float], key: str, value: object) -> None:
    if isinstance(value, bool):
        return
    if isinstance(value, (int, float)):
        found[key] = float(value)
        return
    if isinstance(value, str):
        try:
            found[key] = float(value)
        except ValueError:
            return


def _put_bool(found: dict[str, float], key: str, value: object) -> None:
    if isinstance(value, bool):
        found[key] = 1.0 if value else 0.0


def _put_cov_addopts(found: dict[str, float], value: object) -> None:
    if isinstance(value, list):
        text = " ".join(str(item) for item in value)
    elif isinstance(value, str):
        text = value
    else:
        return
    match = _COV_UNDER.search(text)
    if match:
        found["pytest.cov-fail-under"] = float(match.group(1))


def _walk_numbers(found: dict[str, float], prefix: str, value: object) -> None:
    if isinstance(value, bool):
        return
    if isinstance(value, (int, float)):
        found[prefix] = float(value)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            _walk_numbers(found, f"{prefix}.{key}", item)


def _ini_bool(value: str) -> bool:
    return value.strip().lower() == "true"


def _optional_codes(*values: object) -> frozenset[str] | None:
    seen = False
    found: set[str] = set()
    for value in values:
        if not isinstance(value, list):
            continue
        seen = True
        found.update(str(item) for item in value if isinstance(item, str))
    if not seen:
        return None
    return frozenset(found)


def _codes(*values: object) -> frozenset[str]:
    found: set[str] = set()
    for value in values:
        if isinstance(value, list):
            found.update(str(item) for item in value if isinstance(item, str))
    return frozenset(found)


def _pick(table: object, key: str) -> object:
    if isinstance(table, dict):
        return table.get(key)
    return None


def _off_rules(rules: object) -> frozenset[str]:
    if not isinstance(rules, dict):
        return frozenset()
    disabled: set[str] = set()
    for name, value in rules.items():
        if value in {0, "off", False}:
            disabled.add(str(name))
        elif isinstance(value, list) and value and value[0] in {0, "off", False}:
            disabled.add(str(name))
    return frozenset(disabled)


def _line_with(text: str, needle: str) -> int:
    for index, line in enumerate(text.splitlines(), 1):
        if needle in line:
            return index
    return 1


def _window(before: str, after: str, line: int) -> str:
    def grab(text: str) -> str:
        rows = text.splitlines()
        if not rows:
            return ""
        start = max(0, line - 3)
        end = min(len(rows), line + 2)
        return "\n".join(rows[start:end])

    return f"before:\n{grab(before)}\nafter:\n{grab(after)}"


def _norm(text: str) -> str:
    return " ".join(text.split())


def _unwrap(node: Node) -> Node:
    while node.type == "parenthesized_expression" and len(node.named_children) == 1:
        node = node.named_children[0]
    return node
