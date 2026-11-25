"""Whole-repository post-fix verification: syntax, cross-file imports, cycles, and test gates."""

from __future__ import annotations

import ast
import re
import shutil
import sys
from collections import deque
from pathlib import Path, PurePosixPath

from vibecleaner.collector import collect
from vibecleaner.fix_contract import ExecResult
from vibecleaner.models import Language
from vibecleaner.ts_parse import parse_root
from vibecleaner.verify.failures import parse_failures
from vibecleaner.verify.gates import detect_gates, tool_env
from vibecleaner.verify.sandbox import HostSandbox

_GATE_TIMEOUT_S = 90
_PYTEST_NODEID = re.compile(r"^(?:FAILED|ERROR)\s+(\S+)", re.MULTILINE)
_STYLE_TAG_RE = re.compile(r"<style\b([^>]*)>(.*?)</style>", re.I | re.S)
_CSS_CUSTOM_PROP = re.compile(r"(--[A-Za-z0-9_-]+)\s*:\s*([^;{}]+)")
_COLOR_VALUE = re.compile(
    r"(?:#(?:[0-9a-fA-F]{3,8})\b|\b(?:rgb|rgba|hsl|hsla|oklch|oklab|lab|lch|color-mix)\s*\(|\bvar\s*\(--)",
    re.I,
)
_PATCH_CALL_NAMES = frozenset({"setattr", "patch"})


def canonical_module(path: str) -> str:
    pure = PurePosixPath(path)
    if pure.suffix:
        pure = pure.with_suffix("")
    parts = list(pure.parts)
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def resolve_from_module(importer_path: str, module: str | None, level: int) -> str | None:
    if level == 0:
        return module or ""
    parent_parts = list(PurePosixPath(importer_path).parent.parts)
    ascend = level - 1
    if ascend > len(parent_parts):
        return None
    base = parent_parts[: len(parent_parts) - ascend]
    if module:
        base.extend(module.split("."))
    return ".".join(base)


def module_exports(tree: ast.AST) -> tuple[set[str], bool]:
    """Return (exported_or_bound_names, has_dynamic_exports)."""
    names: set[str] = set()
    dynamic = False

    def walk_suite(stmts: list[ast.stmt]) -> None:
        nonlocal dynamic
        for stmt in stmts:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                names.add(stmt.name)
                if stmt.name == "__getattr__":
                    dynamic = True
            elif isinstance(stmt, ast.Assign):
                for target in stmt.targets:
                    _collect_target_names(target, names)
                    if isinstance(target, ast.Name) and target.id == "__all__":
                        _collect_dunder_all(stmt.value, names)
            elif isinstance(stmt, ast.AnnAssign):
                _collect_target_names(stmt.target, names)
            elif isinstance(stmt, ast.Import):
                for alias in stmt.names:
                    bound = alias.asname or alias.name.split(".")[0]
                    names.add(bound)
            elif isinstance(stmt, ast.ImportFrom):
                for alias in stmt.names:
                    if alias.name == "*":
                        dynamic = True
                    else:
                        names.add(alias.asname or alias.name)
            elif isinstance(stmt, ast.If):
                walk_suite(stmt.body)
                walk_suite(stmt.orelse)
            elif isinstance(stmt, ast.Try):
                walk_suite(stmt.body)
                for handler in stmt.handlers:
                    walk_suite(handler.body)
                walk_suite(stmt.orelse)
                walk_suite(stmt.finalbody)
            elif isinstance(stmt, (ast.With, ast.AsyncWith, ast.For, ast.AsyncFor)):
                walk_suite(stmt.body)
                walk_suite(getattr(stmt, "orelse", []))

    if isinstance(tree, ast.Module):
        walk_suite(tree.body)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "globals":
                dynamic = True
    return names, dynamic


def _collect_target_names(target: ast.AST, out: set[str]) -> None:
    if isinstance(target, ast.Name):
        out.add(target.id)
    elif isinstance(target, (ast.Tuple, ast.List)):
        for elt in target.elts:
            _collect_target_names(elt, out)


def _collect_dunder_all(value: ast.AST | None, out: set[str]) -> None:
    if isinstance(value, (ast.List, ast.Tuple, ast.Set)):
        for elt in value.elts:
            if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                out.add(elt.value)


def _is_type_checking_guard(test: ast.AST) -> bool:
    if isinstance(test, ast.Name) and test.id == "TYPE_CHECKING":
        return True
    if isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING":
        return True
    return False


def top_level_imports(tree: ast.AST) -> list[ast.Import | ast.ImportFrom]:
    found: list[ast.Import | ast.ImportFrom] = []
    if not isinstance(tree, ast.Module):
        return found
    for stmt in tree.body:
        if isinstance(stmt, (ast.Import, ast.ImportFrom)):
            found.append(stmt)
        elif isinstance(stmt, ast.If) and not _is_type_checking_guard(stmt.test):
            for inner in stmt.body + stmt.orelse:
                if isinstance(inner, (ast.Import, ast.ImportFrom)):
                    found.append(inner)
    return found


def all_active_imports(tree: ast.AST) -> list[ast.Import | ast.ImportFrom]:
    """All imports outside ``if TYPE_CHECKING:`` blocks."""
    found: list[ast.Import | ast.ImportFrom] = []

    class Visitor(ast.NodeVisitor):
        def visit_If(self, node: ast.If) -> None:
            if _is_type_checking_guard(node.test):
                for item in node.orelse:
                    self.visit(item)
                return
            self.generic_visit(node)

        def visit_Import(self, node: ast.Import) -> None:
            found.append(node)

        def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
            found.append(node)

    Visitor().visit(tree)
    return found


def verify_static_tree(
    root: Path,
    touched: set[str],
    pre_py_paths: set[str] | None = None,
    pre_files: dict[str, str] | None = None,
) -> str | None:
    """Return a concrete failure reason if syntax, internal imports, dynamic targets, surface invariants, or eager cycles are broken."""
    ctx = collect(root)
    py_trees: dict[str, ast.AST] = {}
    mod_to_path: dict[str, str] = {}
    path_to_mod: dict[str, str] = {}
    top_roots: set[str] = set()

    for source in ctx.files:
        if source.language == Language.PYTHON:
            try:
                tree = ast.parse(source.text, filename=source.path)
            except SyntaxError as exc:
                return f"{source.path}:{exc.lineno or 1} SyntaxError: {exc.msg}"
            py_trees[source.path] = tree
            mod = canonical_module(source.path)
            if mod:
                mod_to_path[mod] = source.path
                path_to_mod[source.path] = mod
                top_roots.add(mod.split(".")[0])
                parts = PurePosixPath(source.path).parts
                if len(parts) > 1:
                    for idx in range(1, len(parts)):
                        pkg = ".".join(parts[:idx])
                        mod_to_path.setdefault(pkg, "")
        elif source.language in {Language.JAVASCRIPT, Language.TYPESCRIPT, Language.TSX}:
            parsed = parse_root(source)
            if parsed is None or parsed.has_error:
                if source.path in touched:
                    return f"{source.path} failed syntax parse after edit"

    if pre_py_paths:
        for old_path in pre_py_paths:
            old_mod = canonical_module(old_path)
            if old_mod:
                top_roots.add(old_mod.split(".")[0])

    exports_cache: dict[str, tuple[set[str], bool]] = {
        path: module_exports(tree) for path, tree in py_trees.items()
    }
    touched_mods = {canonical_module(p) for p in touched if p.endswith(".py") and canonical_module(p)}

    for path, tree in py_trees.items():
        importer_touched = path in touched
        for stmt in all_active_imports(tree):
            if isinstance(stmt, ast.Import):
                for alias in stmt.names:
                    target = alias.name
                    root_pkg = target.split(".")[0]
                    if root_pkg not in top_roots:
                        continue
                    if target not in mod_to_path:
                        if importer_touched or any(
                            t == target or target.startswith(t + ".") or t.startswith(target + ".")
                            for t in touched_mods
                        ):
                            return f"{path}:{stmt.lineno} imports missing module '{target}'"
            elif isinstance(stmt, ast.ImportFrom):
                if stmt.module == "__future__":
                    continue
                resolved = resolve_from_module(path, stmt.module, stmt.level)
                if resolved is None:
                    if importer_touched:
                        return f"{path}:{stmt.lineno} relative import escapes root package"
                    continue
                root_pkg = resolved.split(".")[0] if resolved else ""
                if stmt.level == 0 and root_pkg not in top_roots:
                    continue
                if resolved and resolved not in mod_to_path:
                    if importer_touched or stmt.level > 0 or any(
                        t == resolved or resolved.startswith(t + ".") or t.startswith(resolved + ".")
                        for t in touched_mods
                    ):
                        return f"{path}:{stmt.lineno} imports missing module '{resolved}'"
                    continue
                target_path = mod_to_path.get(resolved, "") if resolved else ""
                target_touched = bool(target_path and target_path in touched) or (resolved in touched_mods)
                if not (importer_touched or target_touched):
                    continue
                for alias in stmt.names:
                    if alias.name == "*":
                        continue
                    submod = f"{resolved}.{alias.name}" if resolved else alias.name
                    if submod in mod_to_path:
                        continue
                    if not target_path:
                        return f"{path}:{stmt.lineno} cannot import '{alias.name}' from namespace '{resolved}'"
                    names, dynamic = exports_cache[target_path]
                    if not dynamic and alias.name not in names:
                        return f"{path}:{stmt.lineno} cannot import '{alias.name}' from '{resolved}' ({target_path})"

    # Check eager top-level cycles involving any touched Python module.
    eager_graph: dict[str, set[str]] = {mod: set() for mod, p in mod_to_path.items() if p}
    for path, tree in py_trees.items():
        mod = path_to_mod.get(path)
        if not mod:
            continue
        edges = eager_graph.setdefault(mod, set())
        for stmt in top_level_imports(tree):
            if isinstance(stmt, ast.Import):
                for alias in stmt.names:
                    _add_target_edges(edges, alias.name, mod_to_path, mod)
            elif isinstance(stmt, ast.ImportFrom) and stmt.module != "__future__":
                resolved = resolve_from_module(path, stmt.module, stmt.level)
                if resolved is None:
                    continue
                if resolved:
                    _add_target_edges(edges, resolved, mod_to_path, mod)
                for alias in stmt.names:
                    if alias.name == "*":
                        continue
                    submod = f"{resolved}.{alias.name}" if resolved else alias.name
                    if submod in mod_to_path:
                        _add_target_edges(edges, submod, mod_to_path, mod)
        edges.discard(mod)

    for start in sorted(touched_mods):
        if start not in eager_graph:
            continue
        cycle = _find_cycle_from(eager_graph, start)
        if cycle is not None:
            return f"circular import introduced: {' -> '.join(cycle)}"

    dynamic_err = _verify_dynamic_and_attr_refs(py_trees, mod_to_path, exports_cache, touched_mods)
    if dynamic_err is not None:
        return dynamic_err

    if pre_files:
        surface_err = verify_surface_health(root, touched, pre_files)
        if surface_err is not None:
            return surface_err

    return None


def _verify_dynamic_and_attr_refs(
    py_trees: dict[str, ast.AST],
    mod_to_path: dict[str, str],
    exports_cache: dict[str, tuple[set[str], bool]],
    touched_mods: set[str],
) -> str | None:
    """Verify monkeypatch/patch dotted string targets and module attribute lookups against touched modules."""
    if not touched_mods:
        return None
    for path, tree in py_trees.items():
        # Track module aliases bound in this file -> canonical module name.
        mod_aliases: dict[str, str] = {}
        for stmt in all_active_imports(tree):
            if isinstance(stmt, ast.Import):
                for alias in stmt.names:
                    if alias.name in mod_to_path and mod_to_path[alias.name]:
                        if alias.asname:
                            mod_aliases[alias.asname] = alias.name
                        elif "." not in alias.name:
                            mod_aliases[alias.name] = alias.name
            elif isinstance(stmt, ast.ImportFrom) and stmt.module != "__future__":
                resolved = resolve_from_module(path, stmt.module, stmt.level)
                if not resolved:
                    continue
                for alias in stmt.names:
                    if alias.name == "*":
                        continue
                    submod = f"{resolved}.{alias.name}"
                    if submod in mod_to_path and mod_to_path[submod]:
                        mod_aliases[alias.asname or alias.name] = submod

        for node in ast.walk(tree):
            # 1. monkeypatch.setattr("pkg.mod.attr", ...) or patch("pkg.mod.attr", ...)
            if isinstance(node, ast.Call) and node.args:
                callee = ""
                if isinstance(node.func, ast.Name):
                    callee = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    callee = node.func.attr
                if callee in _PATCH_CALL_NAMES and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                    target = node.args[0].value
                    if "." in target:
                        mod_part, _, attr = target.rpartition(".")
                        if mod_part in touched_mods and mod_part in mod_to_path:
                            target_path = mod_to_path[mod_part]
                            if target_path:
                                names, dynamic = exports_cache[target_path]
                                if not dynamic and attr not in names:
                                    return f"{path}:{node.lineno} patch target '{target}' missing '{attr}' in '{mod_part}'"
            # 2. Direct module attribute lookup: mod_alias.attr
            elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
                bound_mod = mod_aliases.get(node.value.id)
                if bound_mod and bound_mod in touched_mods:
                    target_path = mod_to_path.get(bound_mod, "")
                    if target_path:
                        names, dynamic = exports_cache[target_path]
                        if not dynamic and node.attr not in names and not node.attr.startswith("__"):
                            submod = f"{bound_mod}.{node.attr}"
                            if submod not in mod_to_path:
                                return f"{path}:{node.lineno} attribute '{node.value.id}.{node.attr}' missing from '{bound_mod}'"
    return None


def _extract_css_blocks(text: str, is_html: bool) -> list[tuple[str, str]]:
    """Return list of (selector, body) pairs for leaf CSS rule blocks."""
    css_chunks: list[str] = []
    if is_html:
        for match in _STYLE_TAG_RE.finditer(text):
            css_chunks.append(match.group(2))
    else:
        css_chunks.append(text)
    blocks: list[tuple[str, str]] = []
    for chunk in css_chunks:
        _collect_leaf_css_blocks(chunk, blocks)
    return blocks


def _collect_leaf_css_blocks(css: str, out: list[tuple[str, str]]) -> None:
    cursor = 0
    while cursor < len(css):
        brace = css.find("{", cursor)
        if brace < 0:
            break
        depth = 1
        end = brace + 1
        while end < len(css) and depth:
            if css[end] == "{":
                depth += 1
            elif css[end] == "}":
                depth -= 1
            end += 1
        if depth != 0:
            break
        selector = " ".join(css[cursor:brace].split())
        body = css[brace + 1 : end - 1]
        if "{" in body:
            _collect_leaf_css_blocks(body, out)
        else:
            out.append((selector, body))
        cursor = end


def _css_custom_color_props(body: str) -> dict[str, str]:
    props: dict[str, str] = {}
    for match in _CSS_CUSTOM_PROP.finditer(body):
        name = match.group(1).strip()
        val = " ".join(match.group(2).strip().split())
        if _COLOR_VALUE.search(val):
            props[name] = val
    return props


def _has_malformed_css_decl(body: str) -> bool:
    """Return True if a leaf CSS block contains a stray non-comment token without a colon (e.g. 'px;')."""
    cleaned = re.sub(r"/\*.*?\*/|\{%.*?%\}|\{\{.*?\}\}", "", body, flags=re.S)
    for part in cleaned.split(";"):
        stripped = part.strip()
        if not stripped or stripped.startswith("@"):
            continue
        if ":" not in stripped:
            return True
    return False


def _css_balanced(css: str) -> bool:
    stripped = re.sub(r"\{%.*?%\}|\{\{.*?\}\}", "", css, flags=re.S)
    depth = 0
    for ch in stripped:
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth < 0:
                return False
    return depth == 0


def verify_surface_health(root: Path, touched: set[str], pre_files: dict[str, str]) -> str | None:
    """Verify HTML/CSS edits did not collapse color palettes, clobber existing tokens, or break CSS/tag balance."""
    for rel in sorted(touched):
        suffix = PurePosixPath(rel).suffix.lower()
        if suffix not in {".html", ".htm", ".css", ".scss"}:
            continue
        dest = root / rel
        if not dest.is_file() or rel not in pre_files:
            continue
        before = pre_files[rel]
        after = dest.read_text(encoding="utf-8")
        is_html = suffix in {".html", ".htm"}
        if is_html:
            if len(re.findall(r"<style\b", after, re.I)) != len(re.findall(r"</style>", after, re.I)):
                return f"{rel} has unbalanced <style> tags after edit"
            if len(re.findall(r"<script\b", after, re.I)) != len(re.findall(r"</script>", after, re.I)):
                return f"{rel} has unbalanced <script> tags after edit"
            for match in _STYLE_TAG_RE.finditer(after):
                if not _css_balanced(match.group(2)):
                    return f"{rel} has unbalanced CSS braces in <style> after edit"
            # Check injected design block does not clobber existing custom properties.
            before_props: set[str] = set()
            for m in _STYLE_TAG_RE.finditer(before):
                if 'data-vibecleaner="design"' not in m.group(1):
                    before_props.update(pm.group(1) for pm in _CSS_CUSTOM_PROP.finditer(m.group(2)))
            for m in _STYLE_TAG_RE.finditer(after):
                if 'data-vibecleaner="design"' in m.group(1):
                    injected = {pm.group(1) for pm in _CSS_CUSTOM_PROP.finditer(m.group(2))}
                    clobbered = sorted(before_props & injected)
                    if clobbered:
                        return f"{rel} injected design tokens clobber existing custom properties: {', '.join(clobbered)}"
        else:
            if not _css_balanced(after):
                return f"{rel} has unbalanced CSS braces after edit"

        # Palette-collapse & malformed-declaration check.
        before_blocks = _extract_css_blocks(before, is_html)
        after_blocks = _extract_css_blocks(after, is_html)
        before_malformed = {
            sel
            for sel, body in before_blocks
            if _has_malformed_css_decl(body)
        }
        for sel, body in after_blocks:
            if sel not in before_malformed and _has_malformed_css_decl(body):
                return f"{rel} introduced malformed CSS declaration in '{sel}'"
        before_by_sel: dict[str, dict[str, str]] = {}
        for sel, body in before_blocks:
            props = _css_custom_color_props(body)
            if len(props) >= 2 and len(set(props.values())) >= 2:
                before_by_sel.setdefault(sel, {}).update(props)
        for sel, body in after_blocks:
            orig_props = before_by_sel.get(sel)
            if not orig_props:
                continue
            new_props = _css_custom_color_props(body)
            shared = [name for name in orig_props if name in new_props]
            if len(shared) >= 2:
                orig_distinct = len({orig_props[n] for n in shared})
                new_distinct = len({new_props[n] for n in shared})
                if orig_distinct >= 2 and new_distinct == 1:
                    return f"{rel} collapsed {orig_distinct} distinct color tokens in '{sel}' into a single value"
    return None


def _add_target_edges(edges: set[str], target: str, mod_to_path: dict[str, str], importer_mod: str = "") -> None:
    parts = target.split(".")
    for idx in range(1, len(parts) + 1):
        prefix = ".".join(parts[:idx])
        if importer_mod and (importer_mod == prefix or importer_mod.startswith(prefix + ".")):
            continue
        if mod_to_path.get(prefix):
            edges.add(prefix)


def _find_cycle_from(graph: dict[str, set[str]], start: str) -> list[str] | None:
    queue: deque[tuple[str, list[str]]] = deque((nxt, [start, nxt]) for nxt in sorted(graph.get(start, ())))
    visited: set[str] = set()
    while queue:
        curr, trail = queue.popleft()
        if curr == start:
            return trail
        if curr in visited:
            continue
        visited.add(curr)
        for nxt in sorted(graph.get(curr, ())):
            if nxt == start or nxt not in visited:
                queue.append((nxt, [*trail, nxt]))
    return None


def _executable_exists(binary: str, search_path: str | None) -> bool:
    if Path(binary).is_file():
        return True
    found = shutil.which(binary, path=search_path) or shutil.which(binary)
    return bool(found and Path(found).is_file())


def _failure_signatures(gate_name: str, parsed: tuple, result: ExecResult) -> frozenset[str]:
    sigs: set[str] = set()
    combined = f"{result.stdout}\n{result.stderr}"
    if gate_name == "pytest":
        for match in _PYTEST_NODEID.finditer(combined):
            sigs.add(f"pytest::{match.group(1)}")
    if not sigs:
        for item in parsed:
            sigs.add(f"{gate_name}::{item.file or ''}::{item.summary}")
    if not sigs:
        first = (result.stderr or result.stdout).strip().splitlines()[:1]
        sigs.add(f"{gate_name}::{first[0] if first else 'failed'}")
    return frozenset(sigs)


def run_local_gates_detailed(root: Path) -> dict[str, tuple[frozenset[str], str]]:
    """Run locally available project gates and return {gate_name: (failure_signatures, summary)} for failing gates."""
    gates = detect_gates(root)
    if not gates:
        return {}
    sandbox = HostSandbox(root)
    env = tool_env("host", root)
    search_path = env.get("PATH")
    failures: dict[str, tuple[frozenset[str], str]] = {}
    for gate in gates:
        result: ExecResult | None = None
        attempts = list(gate.attempts())
        if gate.name == "pytest":
            attempts = [tuple(arg for arg in cmd if arg not in {"-x", "--exitfirst"}) for cmd in attempts]
        if gate.language == "python":
            for command in list(attempts):
                if command and command[0] in {"python", "python3"}:
                    alt = (sys.executable, *command[1:])
                    if alt not in attempts:
                        attempts.append(alt)
        for command in attempts:
            binary = command[0]
            if not _executable_exists(binary, search_path):
                continue
            result = sandbox.run(
                command,
                cwd=root,
                timeout_s=_GATE_TIMEOUT_S,
                network=False,
                env=env or None,
            )
            if result.ok:
                break
            if not result.timed_out and result.returncode == 127:
                result = None
                continue
            if _missing_tool_module(gate.name, result):
                result = None
                continue
            break
        if result is not None and not result.ok:
            parsed = parse_failures(gate, result)
            sigs = _failure_signatures(gate.name, parsed, result)
            summary = parsed[0].summary if parsed else (result.stderr or result.stdout).strip().splitlines()[:1]
            label = summary if isinstance(summary, str) else (summary[0] if summary else "check failed")
            failures[gate.name] = (sigs, label[:240])
    return failures


def gate_regression(
    baseline: dict[str, tuple[frozenset[str], str]],
    post: dict[str, tuple[frozenset[str], str]],
) -> tuple[str, str] | None:
    """Return (gate_name, summary) if ``post`` introduced any failure not present in ``baseline``."""
    for gate_name, (post_sigs, summary) in post.items():
        if gate_name not in baseline:
            return gate_name, summary
        base_sigs, _ = baseline[gate_name]
        new_sigs = sorted(post_sigs - base_sigs)
        if new_sigs:
            return gate_name, f"new failure: {new_sigs[0]}"[:240]
    return None


def run_local_gates(root: Path) -> tuple[str, str] | None:
    """Run locally available project gates without network installs.

    Returns ``(gate_name, summary)`` on the first real gate failure, or ``None`` if all pass/unavailable.
    """
    detailed = run_local_gates_detailed(root)
    for gate_name, (_sigs, summary) in detailed.items():
        return gate_name, summary
    return None


def _missing_tool_module(gate_name: str, result: ExecResult) -> bool:
    combined = f"{result.stdout}\n{result.stderr}"
    for mod in (gate_name, "pytest", "mypy", "ruff", "django"):
        if f"No module named {mod}" in combined or f"No module named '{mod}'" in combined:
            return True
    return False
