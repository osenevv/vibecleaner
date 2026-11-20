"""Project rules loaded from ``<root>/.vibeguard/rules.json``.

The file is institutional memory: each human correction becomes a failing
check. Two kinds of rule are supported.

Pattern rules flag a regular expression. On Python and TS/JS the regex runs
against each line after comments and string contents are blanked, unless the
rule sets ``match_comments``. Globs use gitwildmatch and have no brace
expansion. An optional ``lane`` selects the deslop cleanup lane; when it is
absent the lane is ``ai-slop``.

Import boundaries flag imports in files matching ``from`` whose target is a
forbidden package, whose resolved repo path matches a forbid glob, or whose
resolved repo path is under a non-glob forbid (a path prefix).

A missing file loads as an empty rule set. A broken file raises
:class:`ProjectRulesError` and is never applied in part.
"""

from __future__ import annotations

import json
import os
import posixpath
import re
import tempfile
import warnings
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path, PurePosixPath

import pathspec
from tree_sitter import Node

from vibeguard.collector import walk_repo
from vibeguard.models import (
    PROJECT_RULE_PREFIX,
    RULES,
    Category,
    Finding,
    Language,
    RuleSpec,
    Severity,
    SourceFile,
    register_project_rule,
    unregister_project_rules,
)
from vibeguard.ts_parse import line_text, node_text, parser_for, script_string, walk_tree

__all__ = [
    "DEFAULT_DESLOP_LANE",
    "DESLOP_LANES",
    "BoundaryRule",
    "PatternRule",
    "ProjectRules",
    "ProjectRulesError",
    "add_boundary_rule",
    "add_pattern_rule",
    "apply_project_rules",
    "load_project_rules",
    "rule_hits_preview",
]

DESLOP_LANES: tuple[str, ...] = (
    "dedupe",
    "types",
    "dead-code",
    "cycles",
    "weak-types",
    "defensive-code",
    "legacy",
    "ai-slop",
)
DEFAULT_DESLOP_LANE = "ai-slop"

_ID = re.compile(r"^[a-z0-9][a-z0-9-]{1,48}$")
_SEVERITIES = frozenset({"critical", "high", "medium", "low"})
_CATEGORIES = frozenset({"security", "slop"})
_KINDS = frozenset({"pattern", "import_boundary"})
_LANES = frozenset(DESLOP_LANES)
_GLOB_MARK = re.compile(r"[*?\[\]]")
_CODE_LANGS = frozenset(
    {Language.PYTHON, Language.TYPESCRIPT, Language.TSX, Language.JAVASCRIPT}
)
_TS_EXTS = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts")
_STRING_SKIP = frozenset(
    {"string_start", "string_end", "interpolation", "template_substitution"}
)
_RULES_NAME = Path(".vibeguard") / "rules.json"


class ProjectRulesError(ValueError):
    """``rules.json`` is missing a required field, or a rule is invalid."""


@dataclass
class PatternRule:
    id: str
    pattern: str
    include: list[str]
    message: str
    severity: str = "high"
    category: str = "slop"
    exclude: list[str] = field(default_factory=list)
    remediation: str | None = None
    learned_from: str | None = None
    added: str = ""
    match_comments: bool = False
    lane: str | None = None


@dataclass
class BoundaryRule:
    id: str
    from_globs: list[str]
    forbid: list[str]
    message: str
    severity: str = "high"
    category: str = "security"
    remediation: str | None = None
    learned_from: str | None = None
    added: str = ""


@dataclass
class ProjectRules:
    rules: list[PatternRule | BoundaryRule]
    path: Path


def load_project_rules(root: Path) -> ProjectRules:
    """Load ``.vibeguard/rules.json``. A missing file is an empty rule set.

    The loaded ids replace every previously registered ``P.*`` rule.
    """
    path = _rules_path(root)
    if not path.is_file():
        parsed = ProjectRules(rules=[], path=path)
    else:
        parsed = _parse_document(path, _read_document(path))
    _replace_registered(parsed)
    return parsed


def apply_project_rules(rules: ProjectRules, files: list[SourceFile]) -> list[Finding]:
    """Run ``rules`` against ``files``. Registers each rule id under ``P.``."""
    _register_all(rules)
    return _collect_findings(rules, files)


def _collect_findings(rules: ProjectRules, files: list[SourceFile]) -> list[Finding]:
    findings: list[Finding] = []
    blanked: dict[int, str] = {}
    for rule in rules.rules:
        if isinstance(rule, PatternRule):
            findings.extend(_apply_pattern(rules.path, rule, files, blanked))
        else:
            findings.extend(_apply_boundary(rule, files))
    findings.sort(key=lambda item: (item.file, item.line, item.rule_id, item.message))
    return findings


def add_pattern_rule(
    root: Path,
    rule_id: str,
    pattern: str,
    message: str,
    include: list[str] | None = None,
    exclude: list[str] | None = None,
    severity: str = "high",
    category: str = "slop",
    remediation: str | None = None,
    learned_from: str | None = None,
    lane: str | None = None,
) -> Path:
    """Append a pattern rule and return the rules file path.

    ``include`` defaults to ``["**"]``. The file is created when it does not
    exist. Invalid input or a duplicate id raises and leaves the file as it was.
    """
    body: dict[str, object] = {
        "id": rule_id,
        "kind": "pattern",
        "pattern": pattern,
        "include": ["**"] if include is None else include,
        "exclude": [] if exclude is None else exclude,
        "severity": severity,
        "category": category,
        "message": message,
    }
    if lane is not None:
        body["lane"] = lane
    if remediation is not None:
        body["remediation"] = remediation
    if learned_from is not None:
        body["learned_from"] = learned_from
    body["added"] = date.today().isoformat()
    return _append_rule(root, body)


def add_boundary_rule(
    root: Path,
    rule_id: str,
    from_globs: list[str],
    forbid: list[str],
    message: str,
    severity: str = "high",
    learned_from: str | None = None,
) -> Path:
    """Append an import boundary and return the rules file path.

    Invalid input or a duplicate id raises and leaves the file as it was.
    """
    body: dict[str, object] = {
        "id": rule_id,
        "kind": "import_boundary",
        "from": from_globs,
        "forbid": forbid,
        "severity": severity,
        "message": message,
    }
    if learned_from is not None:
        body["learned_from"] = learned_from
    body["added"] = date.today().isoformat()
    return _append_rule(root, body)


def rule_hits_preview(root: Path, rule: PatternRule | BoundaryRule) -> list[Finding]:
    """Run one unsaved rule over ``root`` via :func:`walk_repo`.

    Does not register the rule and does not change ``RULES``.
    """
    root = Path(root)
    project = ProjectRules(rules=[rule], path=_rules_path(root))
    _parse_document(project.path, {"version": 1, "rules": [_rule_dict(rule)]})
    return _collect_findings(project, walk_repo(root))


def _append_rule(root: Path, body: dict[str, object]) -> Path:
    path = _rules_path(root)
    document = _read_document(path) if path.is_file() else {"version": 1, "rules": []}
    raw_rules = document.get("rules")
    if not isinstance(raw_rules, list):
        raise ProjectRulesError(f"{path}: invalid rules: expected a list")
    updated = dict(document)
    updated["rules"] = [*raw_rules, body]
    parsed = _parse_document(path, updated)
    _atomic_write(path, _dump(updated))
    _replace_registered(parsed)
    return path


def _read_document(path: Path) -> dict[str, object]:
    try:
        text = path.read_text(encoding="utf-8-sig")
    except OSError as exc:
        detail = exc.strerror or str(exc)
        raise ProjectRulesError(f"{path}: cannot read rules file: {detail}") from exc
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ProjectRulesError(f"{path}: invalid JSON: {exc.msg}") from exc
    if not isinstance(data, dict):
        raise ProjectRulesError(f"{path}: invalid rules: top-level value must be an object")
    return data


def _parse_document(path: Path, data: object) -> ProjectRules:
    if not isinstance(data, dict):
        raise ProjectRulesError(f"{path}: invalid rules: top-level value must be an object")
    if data.get("version") != 1:
        raise ProjectRulesError(f"{path}: invalid version: expected 1")
    raw_rules = data.get("rules")
    if not isinstance(raw_rules, list):
        raise ProjectRulesError(f"{path}: invalid rules: expected a list")
    seen: set[str] = set()
    parsed: list[PatternRule | BoundaryRule] = []
    for index, raw in enumerate(raw_rules, start=1):
        rule = _parse_rule(path, raw, index, seen)
        seen.add(rule.id)
        parsed.append(rule)
    return ProjectRules(rules=parsed, path=path)


def _parse_rule(path: Path, raw: object, index: int, seen: set[str]) -> PatternRule | BoundaryRule:
    if not isinstance(raw, dict):
        raise ProjectRulesError(f"{path}: rule #{index} invalid rule: expected an object")
    rule_id = _parse_id(path, raw, index)
    if rule_id in seen:
        raise ProjectRulesError(f"{path}: rule {rule_id!r} invalid id: duplicate")
    kind = raw.get("kind")
    if kind not in _KINDS:
        raise ProjectRulesError(f"{path}: rule {rule_id!r} invalid kind: {kind!r}")
    severity = _required_choice(path, rule_id, raw, "severity", _SEVERITIES)
    added = _optional_str(path, rule_id, raw, "added") or ""
    learned = _optional_str(path, rule_id, raw, "learned_from")
    remediation = _optional_str(path, rule_id, raw, "remediation")
    message = _required_str(path, rule_id, raw, "message")
    if kind == "pattern":
        return PatternRule(
            id=rule_id,
            pattern=_compile_pattern(path, rule_id, raw.get("pattern")),
            include=_string_list(path, rule_id, raw, "include", required=True),
            message=message,
            severity=severity,
            category=_choice(path, rule_id, raw, "category", _CATEGORIES, "slop"),
            exclude=_string_list(path, rule_id, raw, "exclude", required=False),
            remediation=remediation,
            learned_from=learned,
            added=added,
            match_comments=_optional_bool(path, rule_id, raw, "match_comments"),
            lane=_optional_lane(path, rule_id, raw),
        )
    return BoundaryRule(
        id=rule_id,
        from_globs=_string_list(path, rule_id, raw, "from", required=True),
        forbid=_string_list(path, rule_id, raw, "forbid", required=True),
        message=message,
        severity=severity,
        category=_choice(path, rule_id, raw, "category", _CATEGORIES, "security"),
        remediation=remediation,
        learned_from=learned,
        added=added,
    )


def _parse_id(path: Path, raw: dict[str, object], index: int) -> str:
    rule_id = raw.get("id", f"#{index}")
    if isinstance(rule_id, str) and _ID.fullmatch(rule_id):
        return rule_id
    shown = rule_id if isinstance(rule_id, str) else f"#{index}"
    raise ProjectRulesError(f"{path}: rule {shown!r} invalid id: must match {_ID.pattern}")


def _compile_pattern(path: Path, rule_id: str, pattern: object) -> str:
    if not isinstance(pattern, str) or not pattern:
        raise ProjectRulesError(
            f"{path}: rule {rule_id!r} invalid pattern: expected a regular expression"
        )
    try:
        re.compile(pattern)
    except re.error as exc:
        raise ProjectRulesError(f"{path}: rule {rule_id!r} invalid pattern: {exc}") from exc
    return pattern


def _required_choice(
    path: Path, rule_id: str, raw: dict[str, object], field_name: str, allowed: frozenset[str]
) -> str:
    if field_name not in raw:
        raise ProjectRulesError(f"{path}: rule {rule_id!r} invalid {field_name}: missing")
    value = raw[field_name]
    if value not in allowed:
        raise ProjectRulesError(f"{path}: rule {rule_id!r} invalid {field_name}: {value!r}")
    return str(value)


def _choice(
    path: Path,
    rule_id: str,
    raw: dict[str, object],
    field_name: str,
    allowed: frozenset[str],
    default: str,
) -> str:
    if field_name not in raw:
        return default
    value = raw[field_name]
    if value not in allowed:
        raise ProjectRulesError(f"{path}: rule {rule_id!r} invalid {field_name}: {value!r}")
    return str(value)


def _required_str(path: Path, rule_id: str, raw: dict[str, object], field_name: str) -> str:
    value = raw.get(field_name)
    if not isinstance(value, str) or not value.strip():
        raise ProjectRulesError(
            f"{path}: rule {rule_id!r} invalid {field_name}: expected a non-empty string"
        )
    return value


def _optional_str(path: Path, rule_id: str, raw: dict[str, object], field_name: str) -> str | None:
    if field_name not in raw or raw[field_name] is None:
        return None
    value = raw[field_name]
    if not isinstance(value, str):
        raise ProjectRulesError(f"{path}: rule {rule_id!r} invalid {field_name}: expected a string")
    return value


def _optional_lane(path: Path, rule_id: str, raw: dict[str, object]) -> str | None:
    if "lane" not in raw or raw["lane"] is None:
        return None
    value = raw["lane"]
    if value not in _LANES:
        raise ProjectRulesError(f"{path}: rule {rule_id!r} invalid lane: {value!r}")
    return str(value)


def _optional_bool(path: Path, rule_id: str, raw: dict[str, object], field_name: str) -> bool:
    value = raw.get(field_name, False)
    if not isinstance(value, bool):
        raise ProjectRulesError(f"{path}: rule {rule_id!r} invalid {field_name}: expected a boolean")
    return value


def _string_list(
    path: Path, rule_id: str, raw: dict[str, object], field_name: str, *, required: bool
) -> list[str]:
    if field_name not in raw:
        if required:
            raise ProjectRulesError(f"{path}: rule {rule_id!r} invalid {field_name}: missing")
        return []
    value = raw[field_name]
    if not isinstance(value, list) or (required and not value):
        raise ProjectRulesError(
            f"{path}: rule {rule_id!r} invalid {field_name}: expected a non-empty list of strings"
        )
    cleaned: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item:
            raise ProjectRulesError(
                f"{path}: rule {rule_id!r} invalid {field_name}: expected a non-empty list of strings"
            )
        _reject_braces(path, rule_id, field_name, item)
        cleaned.append(item)
    return cleaned


def _reject_braces(path: Path, rule_id: str, field_name: str, item: str) -> None:
    if "{" not in item and "}" not in item:
        return
    raise ProjectRulesError(
        f"{path}: rule {rule_id!r} invalid {field_name}: {item!r} contains '{{' or '}}'; "
        "brace expansion is not supported, list each glob separately"
    )


def _register_all(project: ProjectRules) -> None:
    for rule in project.rules:
        register_project_rule(_spec(rule))


def _replace_registered(project: ProjectRules) -> None:
    specs = [_spec(rule) for rule in project.rules]
    active = {spec.rule_id for spec in specs}
    stale = [
        rule_id
        for rule_id in list(RULES)
        if rule_id.startswith(PROJECT_RULE_PREFIX) and rule_id not in active
    ]
    unregister_project_rules(stale)
    for spec in specs:
        register_project_rule(spec)


def _spec(rule: PatternRule | BoundaryRule) -> RuleSpec:
    try:
        category = Category(rule.category)
        severity = Severity(rule.severity)
    except ValueError as exc:
        raise ProjectRulesError(
            f"rule {rule.id!r} invalid severity or category: {exc}"
        ) from exc
    return RuleSpec(
        rule_id=PROJECT_RULE_PREFIX + rule.id,
        detector="P",
        title=rule.message[:80],
        category=category,
        severity=severity,
        layer=1,
        remediation=rule.remediation or rule.message,
    )


def _apply_pattern(
    path: Path,
    rule: PatternRule,
    files: list[SourceFile],
    blanked: dict[int, str],
) -> list[Finding]:
    try:
        regex = re.compile(rule.pattern)
    except re.error as exc:
        raise ProjectRulesError(f"{path}: rule {rule.id!r} invalid pattern: {exc}") from exc
    include = _compile_globs(tuple(rule.include))
    exclude = _compile_globs(tuple(rule.exclude)) if rule.exclude else None
    spec = _spec(rule)
    findings: list[Finding] = []
    for source in files:
        if not include.match_file(source.path):
            continue
        if exclude is not None and exclude.match_file(source.path):
            continue
        text = source.text if rule.match_comments else _code_for_match(source, blanked)
        for line_no, line in enumerate(text.splitlines(), start=1):
            if regex.search(line) is None:
                continue
            findings.append(
                Finding(
                    rule_id=PROJECT_RULE_PREFIX + rule.id,
                    file=source.path,
                    line=line_no,
                    message=rule.message,
                    snippet=line_text(source.text, line_no),
                    rule_spec=spec,
                )
            )
    return findings


def _code_for_match(source: SourceFile, blanked: dict[int, str]) -> str:
    key = id(source)
    cached = blanked.get(key)
    if cached is not None:
        return cached
    text = source.text if source.language not in _CODE_LANGS else _blank_non_code(source)
    blanked[key] = text
    return text


def _blank_non_code(source: SourceFile) -> str:
    parser = parser_for(source)
    if parser is None:
        return source.text
    tree = parser.parse(source.text.encode("utf-8"))
    spans: list[tuple[int, int]] = []
    for node in walk_tree(tree.root_node):
        if node.type == "comment":
            spans.append((node.start_byte, node.end_byte))
        elif node.type in {"string", "template_string"}:
            spans.extend(_string_content_spans(node))
    return _blank_spans(source.text, spans)


def _string_content_spans(node: Node) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    for child in node.children:
        if child.is_named and child.type not in _STRING_SKIP:
            spans.append((child.start_byte, child.end_byte))
    return spans


def _blank_spans(text: str, spans: list[tuple[int, int]]) -> str:
    if not spans:
        return text
    data = bytearray(text.encode("utf-8"))
    limit = len(data)
    for start, end in spans:
        start = max(0, start)
        end = min(limit, end)
        for index in range(start, end):
            if data[index] not in {0x0A, 0x0D}:
                data[index] = 0x20
    return data.decode("utf-8")


def _apply_boundary(rule: BoundaryRule, files: list[SourceFile]) -> list[Finding]:
    from_spec = _compile_globs(tuple(rule.from_globs))
    packages = [item for item in rule.forbid if not _is_glob(item)]
    glob_items = [item for item in rule.forbid if _is_glob(item)]
    glob_spec = _compile_globs(tuple(glob_items)) if glob_items else None
    spec = _spec(rule)
    findings: list[Finding] = []
    for source in files:
        if not from_spec.match_file(source.path):
            continue
        for line_no, specifier in _imports(source):
            if not _forbidden(specifier, _resolve(source.path, source.language, specifier), packages, glob_spec):
                continue
            findings.append(
                Finding(
                    rule_id=PROJECT_RULE_PREFIX + rule.id,
                    file=source.path,
                    line=line_no,
                    message=f"{rule.message} (imports {specifier})",
                    snippet=line_text(source.text, line_no),
                    rule_spec=spec,
                )
            )
    return findings


def _forbidden(
    specifier: str,
    resolved: list[str],
    packages: list[str],
    glob_spec: pathspec.PathSpec | None,
) -> bool:
    if any(_package_match(specifier, package) for package in packages):
        return True
    if any(_matches_forbid_path(resolved, package) for package in packages):
        return True
    if glob_spec is None:
        return False
    return any(_path_matches(glob_spec, path) for path in resolved)


def _matches_forbid_path(resolved: list[str], forbid: str) -> bool:
    prefixes = _forbid_prefixes(forbid)
    if not prefixes:
        return False
    for path in resolved:
        for form in _alias_forms(path):
            if any(_module_prefix(form, prefix) for prefix in prefixes):
                return True
    return False


def _forbid_prefixes(forbid: str) -> list[str]:
    text = forbid.strip().strip("/")
    if not text or text.startswith("."):
        return []
    bases = [text]
    if _is_dotted_module(text):
        bases.append(text.replace(".", "/"))
    prefixes: list[str] = []
    seen: set[str] = set()
    for base in bases:
        for form in _alias_forms(base):
            if form and form not in seen:
                seen.add(form)
                prefixes.append(form)
    return prefixes


def _is_dotted_module(text: str) -> bool:
    if "/" in text or text.startswith("@") or "." not in text:
        return False
    return all(part.isidentifier() for part in text.split("."))


def _alias_forms(path: str) -> list[str]:
    if path.startswith("src/"):
        rest = path[4:]
        return [path, rest] if rest else [path]
    return [path, f"src/{path}"]


def _module_prefix(path: str, prefix: str) -> bool:
    if not prefix:
        return False
    if path == prefix or path.startswith(prefix + "/"):
        return True
    pure = PurePosixPath(path)
    if not pure.suffix:
        return False
    stem = pure.with_suffix("").as_posix()
    return stem == prefix or stem.startswith(prefix + "/")


def _package_match(specifier: str, package: str) -> bool:
    return specifier == package or specifier.startswith((package + "/", package + "."))


def _path_matches(spec: pathspec.PathSpec, path: str) -> bool:
    if spec.match_file(path):
        return True
    pure = PurePosixPath(path)
    if not pure.suffix:
        return False
    # ``lib/db.ts`` is the same module as the ``lib/db/`` package glob.
    return spec.match_file(pure.with_suffix("").as_posix() + "/index.ts")


def _imports(source: SourceFile) -> list[tuple[int, str]]:
    if source.language == Language.PYTHON:
        return _python_imports(source)
    if source.language in _CODE_LANGS:
        return _script_imports(source)
    return []


def _python_imports(source: SourceFile) -> list[tuple[int, str]]:
    parser = parser_for(source)
    if parser is None:
        return []
    tree = parser.parse(source.text.encode("utf-8"))
    found: list[tuple[int, str]] = []
    for node in walk_tree(tree.root_node):
        if node.type == "import_statement":
            found.extend(_python_import(node))
        elif node.type == "import_from_statement":
            found.extend(_python_from(node))
    return found


def _python_import(node: Node) -> list[tuple[int, str]]:
    line_no = node.start_point[0] + 1
    specs: list[tuple[int, str]] = []
    for index, child in enumerate(node.children):
        if node.field_name_for_child(index) != "name":
            continue
        name = child.child_by_field_name("name") if child.type == "aliased_import" else child
        if name is None:
            continue
        specs.append((line_no, node_text(name)))
    return specs


def _python_from(node: Node) -> list[tuple[int, str]]:
    module = node.child_by_field_name("module_name")
    if module is None:
        return []
    line_no = node.start_point[0] + 1
    if module.type != "relative_import":
        return [(line_no, node_text(module))]
    prefix = next((child for child in module.children if child.type == "import_prefix"), None)
    dotted = next((child for child in module.children if child.type == "dotted_name"), None)
    dots = node_text(prefix).count(".") if prefix is not None else 1
    if dotted is not None:
        return [(line_no, ("." * dots) + node_text(dotted))]
    names = []
    for index, child in enumerate(node.children):
        if node.field_name_for_child(index) != "name":
            continue
        target = child.child_by_field_name("name") if child.type == "aliased_import" else child
        if target is not None:
            names.append(node_text(target).split(".")[0])
    if not names:
        return [(line_no, "." * dots)]
    return [(line_no, ("." * dots) + name) for name in names]


def _script_imports(source: SourceFile) -> list[tuple[int, str]]:
    parser = parser_for(source)
    if parser is None:
        return []
    tree = parser.parse(source.text.encode("utf-8"))
    found: list[tuple[int, str]] = []
    for node in walk_tree(tree.root_node):
        if node.type in {"import_statement", "export_statement"}:
            spec = _static_source(node)
        elif node.type == "call_expression":
            spec = _dynamic_source(node)
        else:
            continue
        if spec:
            found.append((node.start_point[0] + 1, spec))
    return found


def _static_source(node: Node) -> str | None:
    source = node.child_by_field_name("source")
    if source is None:
        return None
    return _clean_specifier(script_string(source))


def _dynamic_source(node: Node) -> str | None:
    func = node.child_by_field_name("function")
    if func is None:
        return None
    if func.type == "identifier" and node_text(func) == "require":
        pass
    elif func.type == "import" or node_text(func) == "import":
        pass
    else:
        return None
    args = node.child_by_field_name("arguments")
    if args is None or not args.named_children:
        return None
    first = args.named_children[0]
    if first.type != "string":
        return None
    return _clean_specifier(script_string(first))


def _clean_specifier(specifier: str | None) -> str | None:
    if specifier is None:
        return None
    cleaned = specifier.split("?", 1)[0].split("#", 1)[0].strip()
    return cleaned or None


def _resolve(file_path: str, language: Language, specifier: str) -> list[str]:
    if language == Language.PYTHON:
        return _resolve_python(file_path, specifier)
    return _resolve_script(file_path, specifier)


def _resolve_python(file_path: str, specifier: str) -> list[str]:
    if specifier.startswith("."):
        dots = len(specifier) - len(specifier.lstrip("."))
        rest = specifier[dots:]
        parts = list(PurePosixPath(file_path).parent.parts)
        up = dots - 1
        if up > len(parts):
            return []
        if up:
            parts = parts[:-up]
        if rest:
            parts.extend(rest.split("."))
        if not parts:
            return []
        base = "/".join(parts)
    else:
        base = "/".join(part for part in specifier.split(".") if part)
        if not base:
            return []
    return [f"{base}.py", f"{base}/__init__.py"]


def _resolve_script(file_path: str, specifier: str) -> list[str]:
    if specifier.startswith("@/"):
        rest = specifier[2:]
        return [*_expand(f"src/{rest}"), *_expand(rest)]
    if specifier.startswith(("./", "../")):
        parent = PurePosixPath(file_path).parent.as_posix()
        joined = specifier if parent == "." else f"{parent}/{specifier}"
        return _expand(joined)
    return []


def _expand(base: str) -> list[str]:
    norm = posixpath.normpath(base)
    if norm == ".." or norm.startswith("../"):
        return []
    lowered = norm.lower()
    if any(lowered.endswith(ext) for ext in _TS_EXTS):
        return [norm]
    paths = [norm + ext for ext in _TS_EXTS]
    paths.extend(f"{norm}/index{ext}" for ext in _TS_EXTS)
    return paths


def _is_glob(pattern: str) -> bool:
    return _GLOB_MARK.search(pattern) is not None


def _compile_globs(patterns: tuple[str, ...]) -> pathspec.PathSpec:
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", message="GitWildMatchPattern", category=DeprecationWarning)
        return pathspec.PathSpec.from_lines("gitwildmatch", list(patterns))


def _rule_dict(rule: PatternRule | BoundaryRule) -> dict[str, object]:
    if isinstance(rule, PatternRule):
        body: dict[str, object] = {
            "id": rule.id,
            "kind": "pattern",
            "pattern": rule.pattern,
            "include": rule.include,
            "exclude": rule.exclude,
            "severity": rule.severity,
            "category": rule.category,
            "message": rule.message,
        }
        if rule.lane is not None:
            body["lane"] = rule.lane
        if rule.match_comments:
            body["match_comments"] = True
    else:
        body = {
            "id": rule.id,
            "kind": "import_boundary",
            "from": rule.from_globs,
            "forbid": rule.forbid,
            "severity": rule.severity,
            "category": rule.category,
            "message": rule.message,
        }
    if rule.remediation is not None:
        body["remediation"] = rule.remediation
    if rule.learned_from is not None:
        body["learned_from"] = rule.learned_from
    if rule.added:
        body["added"] = rule.added
    return body


def _rules_path(root: Path) -> Path:
    return Path(root) / _RULES_NAME


def _dump(data: dict[str, object]) -> str:
    return json.dumps(data, indent=2, ensure_ascii=False) + "\n"


def _atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    tmp = Path(name)
    replaced = False
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
        replaced = True
    finally:
        if not replaced:
            tmp.unlink(missing_ok=True)
