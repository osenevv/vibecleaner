"""Rewrite the nine structural slop indicators.

Each repair is a behavior-preserving edit a second run does not repeat.
A high-risk file is left untouched.
"""

from __future__ import annotations

import ast
from collections import deque
import re
from pathlib import Path, PurePosixPath

from vibecleaner.behavior import behavior_holds
from vibecleaner.collector import collect
from vibecleaner.deslop import _is_test_path
from vibecleaner.models import Language
from vibecleaner.repo_health import canonical_module, module_exports, resolve_from_module
from vibecleaner.risk import RiskTier, classify_file

_LAYER_DIRS = frozenset({"utils", "helpers", "services", "controllers", "repositories"})
_RANK = {
    "models": 0,
    "domain": 0,
    "entities": 0,
    "schema": 0,
    "schemas": 0,
    "types": 0,
    "constants": 0,
    "consts": 0,
    "keys": 0,
    "repositories": 1,
    "repository": 1,
    "db": 1,
    "database": 1,
    "storage": 1,
    "store": 1,
    "services": 2,
    "service": 2,
    "core": 2,
    "engine": 2,
    "controllers": 3,
    "controller": 3,
    "routes": 3,
    "api": 3,
    "views": 3,
    "handlers": 3,
    "web": 3,
    "cli": 3,
    "gui": 3,
    "desktop": 3,
}
_BUILTINS = frozenset(
    {"True", "False", "None", "len", "range", "int", "str", "min", "max", "sum", "abs", "bool", "list", "dict"}
)
_KEY_STOP = frozenset(
    {
        "rule_id",
        "user_id",
        "content_type",
        "created_at",
        "updated_at",
        "started_at",
        "finished_at",
        "deleted_at",
        "expires_at",
        "status_code",
        "request_id",
        "session_id",
        "profile_id",
        "recording_id",
    }
)
_ROUTE_VERBS = frozenset({"get", "post", "put", "patch", "delete"})
_SQL = re.compile(r"\b(?:SELECT|INSERT|UPDATE|DELETE)\b")


def _merge_origins(
    target: dict[str, tuple[str, tuple[str, ...]]],
    batch: dict[str, tuple[str, tuple[str, ...]]],
) -> None:
    for path, (original, rules) in batch.items():
        if path not in target:
            target[path] = (original, rules)
        else:
            previous, previous_rules = target[path]
            target[path] = (previous, tuple(dict.fromkeys((*previous_rules, *rules))))


def repair_structure(root: Path, skip_rules: frozenset[str] = frozenset()) -> dict[str, tuple[str, tuple[str, ...]]]:
    """Apply every structural repair under ``root``. Return the originals that changed."""
    origins: dict[str, tuple[str, tuple[str, ...]]] = {}
    for _ in range(4):
        batch = _once(root, skip_rules)
        if not batch:
            break
        _merge_origins(origins, batch)
    return origins


def _once(root: Path, skip_rules: frozenset[str]) -> dict[str, tuple[str, tuple[str, ...]]]:
    files = _python(root)
    origins: dict[str, tuple[str, tuple[str, ...]]] = {}
    for repair in (
        _passthroughs,
        _duplicates,
        _illegal_states,
        _boundary,
        _coupling,
        _layering,
        _god_files,
        _layer_folders,
    ):
        _merge_origins(origins, repair(root, files, skip_rules))
        files = _python(root)
    _merge_origins(origins, _script_boundary(root, skip_rules))
    return origins


def _python(root: Path) -> dict[str, str]:
    found: dict[str, str] = {}
    for source in collect(root).files:
        if source.language != Language.PYTHON or _is_test_path(source.path):
            continue
        found[source.path] = source.text
    return found


def _all_python(root: Path) -> dict[str, str]:
    found: dict[str, str] = {}
    for source in collect(root).files:
        if source.language == Language.PYTHON:
            found[source.path] = source.text
    return found


def _commit(
    root: Path,
    before: dict[str, str],
    after: dict[str, str],
    rule: str,
    skip_rules: frozenset[str],
    delete: frozenset[str] = frozenset(),
    files: dict[str, str] | None = None,
) -> dict[str, tuple[str, tuple[str, ...]]]:
    if rule in skip_rules:
        return {}
    changed = {path: text for path, text in after.items() if before.get(path) != text}
    if not changed and not delete:
        return {}
    for path in list(changed) + list(delete):
        original = before.get(path, "")
        if classify_file(path, original) is RiskTier.HIGH:
            return {}
        if path.endswith(".py") and path in changed and _parsed(changed[path]) is None:
            return {}
        if path.endswith(".py") and path in before and path in changed and before[path] and not behavior_holds(before[path], changed[path]):
            return {}
    origins: dict[str, tuple[str, tuple[str, ...]]] = {}
    for path, text in changed.items():
        destination = root / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(text, encoding="utf-8")
        origins[path] = (before.get(path, ""), (rule,))
        if files is not None and not _is_test_path(path):
            files[path] = text
    for path in delete:
        destination = root / path
        if destination.is_file():
            destination.unlink()
        if path not in origins:
            origins[path] = (before.get(path, ""), (rule,))
        if files is not None:
            files.pop(path, None)
    return origins


def _passthroughs(root: Path, files: dict[str, str], skip_rules: frozenset[str]) -> dict[str, tuple[str, tuple[str, ...]]]:
    origins: dict[str, tuple[str, tuple[str, ...]]] = {}
    all_py = {**_all_python(root), **files}
    for path in list(files):
        text = files.get(path)
        if text is None:
            continue
        tree = _parsed(text)
        if tree is None:
            continue
        wrappers = _wrapper_map(tree)
        if not wrappers:
            continue
        updated = text
        external: dict[str, str] = {}
        aborted = False
        source_module = canonical_module(path)
        for name, target in wrappers.items():
            if source_module and _has_unrewritable_symbol_ref(all_py, path, source_module, name):
                continue
            importers = {
                other: source
                for other, source in all_py.items()
                if other != path and source_module and _imports_symbol_from(other, source, source_module, name)
            }
            if not name.startswith("_") and not importers and not _calls_name(tree, name):
                continue
            home = _defining_module(text, path, target)
            if importers and not home:
                continue
            retargeted_map: dict[str, str] = {}
            for other, source in importers.items():
                base = external.get(other, source)
                retargeted = _retarget_import_source(other, base, name, target, source_module, home)
                if retargeted == base:
                    aborted = True
                    break
                retargeted = _rename_ast_name_refs(retargeted, name, target)
                retargeted_map[other] = retargeted
            if aborted:
                break
            updated = _delete_function(updated, name)
            updated = _rename_ast_name_refs(updated, name, target)
            updated = _retarget_imports(updated, name, target)
            updated = re.sub(rf"""["']{re.escape(name)}["']\s*,?\s*""", "", updated)
            external.update(retargeted_map)
        if aborted:
            continue
        after = {path: updated, **external}
        before = {path: text, **{other: all_py[other] for other in external}}
        applied = _commit(root, before, after, "D6a.passthrough_wrapper", skip_rules, files=files)
        if applied:
            _merge_origins(origins, applied)
            for other, new_src in after.items():
                all_py[other] = new_src
    return origins


def _wrapper_map(tree: ast.AST) -> dict[str, str]:
    found: dict[str, str] = {}
    for node in tree.body if isinstance(tree, ast.Module) else []:
        if not isinstance(node, ast.FunctionDef) or node.decorator_list:
            continue
        target = _wrapper_target(node)
        if target is not None and target != node.name:
            found[node.name] = target
    return found


def _calls_name(tree: ast.AST, name: str) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == name:
            return True
    return False


def _wrapper_target(fn: ast.FunctionDef) -> str | None:
    statements = [stmt for stmt in fn.body if not _docstring(stmt)]
    if len(statements) != 1 or not isinstance(statements[0], ast.Return) or not isinstance(statements[0].value, ast.Call):
        return None
    call = statements[0].value
    if not isinstance(call.func, ast.Name) or call.keywords and not _star_forward(fn, call):
        return None
    if _star_forward(fn, call):
        return call.func.id
    params = [arg.arg for arg in fn.args.args]
    if fn.args.vararg or fn.args.kwarg or fn.args.kwonlyargs or fn.args.defaults:
        return None
    if [arg.id if isinstance(arg, ast.Name) else "" for arg in call.args] != params:
        return None
    if call.keywords:
        return None
    return call.func.id


def _star_forward(fn: ast.FunctionDef, call: ast.Call) -> bool:
    if fn.args.vararg is None or fn.args.kwarg is None or len(fn.args.args) != 0:
        return False
    if len(call.args) != 1 or len(call.keywords) != 1:
        return False
    star, keyword = call.args[0], call.keywords[0]
    return (
        isinstance(star, ast.Starred)
        and isinstance(star.value, ast.Name)
        and star.value.id == fn.args.vararg.arg
        and keyword.arg is None
        and isinstance(keyword.value, ast.Name)
        and keyword.value.id == fn.args.kwarg.arg
    )


def _duplicates(root: Path, files: dict[str, str], skip_rules: frozenset[str]) -> dict[str, tuple[str, tuple[str, ...]]]:
    all_py = {**_all_python(root), **files}
    graph, known = _import_graph(all_py)
    grouped: dict[str, list[tuple[str, ast.FunctionDef]]] = {}
    for path, text in files.items():
        tree = _parsed(text)
        if tree is None:
            continue
        for node in tree.body if isinstance(tree, ast.Module) else []:
            if not isinstance(node, ast.FunctionDef) or node.decorator_list:
                continue
            key = _body_key(node)
            if key:
                grouped.setdefault(key, []).append((path, node))
    origins: dict[str, tuple[str, tuple[str, ...]]] = {}
    for copies in grouped.values():
        if len(copies) < 2:
            continue
        ordered = sorted(copies, key=lambda item: (item[0], item[1].lineno))
        keeper_path, keeper = ordered[0]
        rule = "D6a.shotgun_surgery" if len(ordered) >= 3 else "D9.duplicate_function"
        keeper_mod = canonical_module(keeper_path)
        for path, fn in ordered[1:]:
            if path == keeper_path and fn.name == keeper.name:
                continue
            if path != keeper_path and not _safe_import_edge(graph, known, path, keeper_path):
                continue
            text = files.get(path)
            if text is None:
                continue
            updated = _delete_function(text, fn.name)
            if path != keeper_path:
                imported = keeper.name if fn.name == keeper.name else f"{keeper.name} as {fn.name}"
                updated = _add_import(updated, keeper_mod, imported)
            elif fn.name != keeper.name:
                updated = _rename_calls(updated, fn.name, keeper.name)
            applied = _commit(root, {path: text}, {path: updated}, rule, skip_rules, files=files)
            if applied:
                _merge_origins(origins, applied)
                if path != keeper_path:
                    _record_import_edge(graph, known, path, keeper_path)
    return origins


def _body_key(fn: ast.FunctionDef) -> str:
    body = [stmt for stmt in fn.body if not _docstring(stmt)]
    if len(body) < 4:
        return ""
    mapping = {arg.arg: f"arg{index}" for index, arg in enumerate(fn.args.args)}
    copied = ast.Module(body=[ast.fix_missing_locations(copy) for copy in _cloned(body)], type_ignores=[])
    for node in ast.walk(copied):
        if isinstance(node, ast.Name) and node.id in mapping:
            node.id = mapping[node.id]
        elif isinstance(node, ast.arg) and node.arg in mapping:
            node.arg = mapping[node.arg]
    return ast.dump(copied)


def _cloned(body: list[ast.stmt]) -> list[ast.stmt]:
    import copy

    return [copy.deepcopy(stmt) for stmt in body]


def _illegal_states(root: Path, files: dict[str, str], skip_rules: frozenset[str]) -> dict[str, tuple[str, tuple[str, ...]]]:
    origins: dict[str, tuple[str, tuple[str, ...]]] = {}
    for path in list(files):
        text = files[path]
        tree = _parsed(text)
        if tree is None:
            continue
        updated = text
        changed = False
        for node in tree.body if isinstance(tree, ast.Module) else []:
            if not isinstance(node, ast.FunctionDef):
                continue
            for arg in node.args.args:
                literals = _closed_strings(node, arg.arg)
                if len(literals) < 2 or not _rejects_other(node, arg.arg):
                    continue
                if arg.annotation is not None and not _is_str(arg.annotation):
                    continue
                rendered = "Literal[" + ", ".join(repr(item) for item in literals) + "]"
                updated = _annotate(updated, node.name, arg.arg, rendered)
                changed = True
        if changed:
            updated = _add_import(updated, "typing", "Literal")
            _merge_origins(origins, _commit(root, {path: text}, {path: updated}, "D6a.illegal_state", skip_rules, files=files))
    return origins


def _closed_strings(fn: ast.FunctionDef, name: str) -> tuple[str, ...]:
    found: list[str] = []
    for node in ast.walk(fn):
        if not isinstance(node, ast.Compare) or len(node.ops) != 1 or not isinstance(node.ops[0], ast.Eq):
            continue
        sides = [node.left, *node.comparators]
        names = [side for side in sides if isinstance(side, ast.Name) and side.id == name]
        constants = [side.value for side in sides if isinstance(side, ast.Constant) and isinstance(side.value, str)]
        if names and len(constants) == 1:
            found.append(constants[0])
    return tuple(dict.fromkeys(found))


def _rejects_other(fn: ast.FunctionDef, name: str) -> bool:
    for node in ast.walk(fn):
        if isinstance(node, ast.Raise) and _mentions(node.exc, name):
            return True
    return False


def _mentions(node: ast.AST | None, name: str) -> bool:
    if node is None:
        return False
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and child.id == name:
            return True
    return False


def _is_str(node: ast.AST) -> bool:
    return isinstance(node, ast.Name) and node.id == "str"


def _annotate(text: str, fn_name: str, arg_name: str, rendered: str) -> str:
    pattern = re.compile(rf"(def {re.escape(fn_name)}\s*\([^)]*?\b{re.escape(arg_name)}\b)(\s*:\s*str)?")
    return pattern.sub(rf"\1: {rendered}", text, count=1)


def _boundary(root: Path, files: dict[str, str], skip_rules: frozenset[str]) -> dict[str, tuple[str, tuple[str, ...]]]:
    origins: dict[str, tuple[str, tuple[str, ...]]] = {}
    for path in list(files):
        text = files[path]
        tree = _parsed(text)
        if tree is None:
            continue
        updated = text
        for node in tree.body if isinstance(tree, ast.Module) else []:
            if not isinstance(node, ast.FunctionDef) or not _route(node):
                continue
            segment = ast.get_source_segment(text, node) or ""
            if "missing required field" in segment or "model_validate" in segment or "BaseModel" in segment:
                continue
            binding = _body_binding(node)
            if binding is None:
                continue
            keys = _body_keys(node, binding)
            if not keys:
                continue
            check = _required_check(binding, keys)
            updated = _insert_after_assign(updated, node, binding, check)
        if updated != text:
            _merge_origins(origins, _commit(root, {path: text}, {path: updated}, "D9.boundary_schema", skip_rules, files=files))
    return origins


def _route(fn: ast.FunctionDef) -> bool:
    for decorator in fn.decorator_list:
        target = decorator.func if isinstance(decorator, ast.Call) else decorator
        if isinstance(target, ast.Attribute) and target.attr in _ROUTE_VERBS:
            return True
    return False


def _body_binding(fn: ast.FunctionDef) -> str | None:
    for stmt in fn.body:
        if not isinstance(stmt, ast.Assign) or len(stmt.targets) != 1 or not isinstance(stmt.targets[0], ast.Name):
            continue
        value = stmt.value
        if isinstance(value, ast.Call) and isinstance(value.func, ast.Attribute) and value.func.attr in {"get_json", "json"}:
            return stmt.targets[0].id
        if isinstance(value, ast.Attribute) and value.attr == "json" and isinstance(value.value, ast.Name):
            return stmt.targets[0].id
    return None


def _body_keys(fn: ast.FunctionDef, binding: str) -> tuple[str, ...]:
    found: list[str] = []
    for node in ast.walk(fn):
        if not isinstance(node, ast.Subscript) or not isinstance(node.value, ast.Name) or node.value.id != binding:
            continue
        if isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str):
            found.append(node.slice.value)
    return tuple(dict.fromkeys(found))


def _required_check(binding: str, keys: tuple[str, ...]) -> str:
    rendered = ", ".join(repr(key) for key in keys)
    return (
        f"if not isinstance({binding}, dict) or any(key not in {binding} for key in ({rendered},)):\n"
        f"    raise ValueError(\"missing required field\")"
    )


def _insert_after_assign(text: str, fn: ast.FunctionDef, binding: str, check: str) -> str:
    lines = text.splitlines()
    for stmt in fn.body:
        if not isinstance(stmt, ast.Assign):
            continue
        segment = ast.get_source_segment(text, stmt) or ""
        if binding not in segment:
            continue
        indent = re.match(r"\s*", lines[stmt.lineno - 1]).group(0) if stmt.lineno <= len(lines) else "    "
        block = "\n".join(indent + line if line else line for line in check.splitlines())
        lines.insert(stmt.end_lineno or stmt.lineno, block)
        return "\n".join(lines) + ("\n" if text.endswith("\n") else "")
    return text


def _script_boundary(root: Path, skip_rules: frozenset[str]) -> dict[str, tuple[str, tuple[str, ...]]]:
    if "D9.boundary_schema" in skip_rules:
        return {}
    origins: dict[str, tuple[str, tuple[str, ...]]] = {}
    for source in collect(root).files:
        if source.language not in {Language.JAVASCRIPT, Language.TYPESCRIPT, Language.TSX} or _is_test_path(source.path):
            continue
        text = source.text
        if "missing required field" in text or "safeParse" in text or "zod" in text:
            continue
        match = re.search(r"\breq\.body\.([A-Za-z_][A-Za-z0-9_]*)", text)
        if match is None:
            continue
        start = text.rfind("function", 0, match.start())
        brace = text.find("{", start if start >= 0 else 0)
        if brace < 0:
            continue
        field = match.group(1)
        insert = (
            f'\n  if (req.body == null || req.body.{field} == null) {{\n'
            f'    throw new Error("missing required field");\n  }}\n'
        )
        updated = text[: brace + 1] + insert + text[brace + 1 :]
        if classify_file(source.path, text) is RiskTier.HIGH:
            continue
        source.abs_path.write_text(updated, encoding="utf-8")
        origins[source.path] = (text, ("D9.boundary_schema",))
    return origins


def _coupling(root: Path, files: dict[str, str], skip_rules: frozenset[str]) -> dict[str, tuple[str, tuple[str, ...]]]:
    all_py = {**_all_python(root), **files}
    graph, known = _import_graph(all_py)
    owners: dict[str, list[str]] = {}
    for path, text in files.items():
        tree = _parsed(text)
        if tree is None:
            continue
        for key in _keys(tree):
            if key in _KEY_STOP or "_" not in key or not re.fullmatch(r"[a-z][a-z0-9_]{5,}", key):
                continue
            owners.setdefault(key, []).append(path)
    origins: dict[str, tuple[str, tuple[str, ...]]] = {}
    for key, paths in owners.items():
        unique = [path for path in dict.fromkeys(paths) if path in files]
        if not 2 <= len(unique) <= 4:
            continue
        if any(_key_is_mixed(files[path], key) for path in unique):
            continue
        const = key.upper()
        if any(_symbol_exists(files[path], const) for path in unique):
            continue
        home = _choose_coupling_home(unique, graph, known)
        if home is None:
            continue
        home_module = canonical_module(home)
        if not home_module:
            continue
        before = {path: files[path] for path in unique}
        after: dict[str, str] = {}
        valid = True
        for path in unique:
            current = files[path]
            replaced = _replace_key(current, key, const)
            if replaced == current:
                valid = False
                break
            if path == home:
                updated = _insert_assign(replaced, f'{const} = "{key}"')
            else:
                updated = _add_import(replaced, home_module, const)
            after[path] = updated
        if not valid:
            continue
        applied = _commit(root, before, after, "D6a.implicit_coupling", skip_rules, files=files)
        if applied:
            _merge_origins(origins, applied)
            for path in unique:
                if path != home:
                    _record_import_edge(graph, known, path, home)
    return origins


def _choose_coupling_home(
    unique: list[str],
    graph: dict[str, set[str]],
    known: set[str],
) -> str | None:
    def priority(item: tuple[int, str]) -> tuple[int, int, int, int]:
        idx, path = item
        stem = PurePosixPath(path).stem
        is_const = 0 if stem in {"constants", "consts", "keys"} else 1
        rank = _rank(path)
        rank_key = rank if rank is not None else 10
        out_deg = len(graph.get(canonical_module(path), ()))
        return (is_const, rank_key, out_deg, idx)

    def _allowed_dependency(other: str, candidate: str) -> bool:
        if not _safe_import_edge(graph, known, other, candidate):
            return False
        other_mod = canonical_module(other)
        cand_mod = canonical_module(candidate)
        # If other already depends on candidate (directly or transitively), no new coupling direction is invented.
        if other_mod and cand_mod and _reaches(graph, {other_mod}, cand_mod):
            return True
        cand_rank = _rank(candidate)
        other_rank = _rank(other)
        # Dedicated foundation/storage layers (rank 0-1) can safely own shared keys for higher/unranked layers.
        if cand_rank is not None and cand_rank <= 1 and (other_rank is None or cand_rank <= other_rank):
            return True
        if cand_rank is not None and other_rank is not None and cand_rank < other_rank:
            return True
        # Flat standalone scripts with no package hierarchy (e.g. a.py + b.py) stay allowed.
        if cand_rank is None and other_rank is None and "." not in cand_mod and "." not in other_mod:
            return True
        return False

    for _idx, candidate in sorted(enumerate(unique), key=priority):
        if all(_allowed_dependency(other, candidate) for other in unique if other != candidate):
            return candidate
    return None


def _symbol_exists(text: str, name: str) -> bool:
    tree = _parsed(text)
    if tree is None:
        return True
    names, _ = module_exports(tree)
    if name in names:
        return True
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id == name:
            return True
    return False


def _import_graph(all_files: dict[str, str]) -> tuple[dict[str, set[str]], set[str]]:
    known = {canonical_module(path) for path in all_files if canonical_module(path)}
    graph: dict[str, set[str]] = {mod: set() for mod in known}
    for path, text in all_files.items():
        mod = canonical_module(path)
        if not mod:
            continue
        tree = _parsed(text)
        if tree is None:
            continue
        edges = graph.setdefault(mod, set())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    _add_chain(edges, alias.name, known)
            elif isinstance(node, ast.ImportFrom) and node.module != "__future__":
                resolved = resolve_from_module(path, node.module, node.level)
                if not resolved:
                    continue
                _add_chain(edges, resolved, known)
                for alias in node.names:
                    if alias.name == "*":
                        continue
                    sub = f"{resolved}.{alias.name}"
                    if sub in known:
                        _add_chain(edges, sub, known)
        edges.discard(mod)
    return graph, known


def _add_chain(edges: set[str], target: str, known: set[str]) -> None:
    parts = target.split(".")
    for idx in range(1, len(parts) + 1):
        prefix = ".".join(parts[:idx])
        if prefix in known:
            edges.add(prefix)


def _target_nodes(target_path: str, known: set[str]) -> set[str]:
    mod = canonical_module(target_path)
    out: set[str] = set()
    if mod:
        _add_chain(out, mod, known)
    return out


def _safe_import_edge(
    graph: dict[str, set[str]],
    known: set[str],
    importer_path: str,
    target_path: str,
) -> bool:
    imp_rank = _rank(importer_path)
    tgt_rank = _rank(target_path)
    if imp_rank is not None and tgt_rank is not None and tgt_rank > imp_rank:
        return False
    if imp_rank is not None and imp_rank <= 1 and tgt_rank is None:
        return False
    imp_mod = canonical_module(importer_path)
    tgt_mod = canonical_module(target_path)
    if not imp_mod or not tgt_mod or imp_mod == tgt_mod:
        return False
    targets = _target_nodes(target_path, known)
    if imp_mod in targets:
        return False
    blocked = {imp_mod}
    parts = imp_mod.split(".")
    for idx in range(1, len(parts)):
        pkg = ".".join(parts[:idx])
        if pkg in known and _reaches(graph, {pkg}, imp_mod):
            blocked.add(pkg)
    return not _reaches_any(graph, targets, blocked)


def _record_import_edge(
    graph: dict[str, set[str]],
    known: set[str],
    importer_path: str,
    target_path: str,
) -> None:
    imp_mod = canonical_module(importer_path)
    if not imp_mod:
        return
    edges = graph.setdefault(imp_mod, set())
    edges.update(_target_nodes(target_path, known))
    edges.discard(imp_mod)


def _reaches(graph: dict[str, set[str]], starts: set[str], goal: str) -> bool:
    return _reaches_any(graph, starts, {goal})


def _reaches_any(graph: dict[str, set[str]], starts: set[str], goals: set[str]) -> bool:
    if starts & goals:
        return True
    queue: deque[str] = deque(starts)
    visited = set(starts)
    while queue:
        curr = queue.popleft()
        for nxt in graph.get(curr, ()):
            if nxt in goals:
                return True
            if nxt not in visited:
                visited.add(nxt)
                queue.append(nxt)
    return False


def _keys(tree: ast.AST) -> set[str]:
    found: set[str] = set()

    class Walk(ast.NodeVisitor):
        def visit_Subscript(self, node: ast.Subscript) -> None:
            if isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str):
                found.add(node.slice.value)
            self.generic_visit(node)

        def visit_Dict(self, node: ast.Dict) -> None:
            for key in node.keys:
                if isinstance(key, ast.Constant) and isinstance(key.value, str):
                    found.add(key.value)
            self.generic_visit(node)

        def visit_Call(self, node: ast.Call) -> None:
            func = node.func
            if isinstance(func, ast.Attribute) and func.attr in {"get", "pop", "setdefault"} and node.args:
                arg = node.args[0]
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    found.add(arg.value)
            self.generic_visit(node)

    Walk().visit(tree)
    return found


def _replace_key(text: str, key: str, const: str) -> str:
    tree = _parsed(text)
    if tree is None:
        return text
    spans = _key_spans(tree, key)
    if not spans:
        return text
    lines = text.splitlines()
    for lineno, start, end in sorted(spans, reverse=True):
        row = lines[lineno - 1]
        lines[lineno - 1] = row[:start] + const + row[end:]
    return "\n".join(lines) + ("\n" if text.endswith("\n") else "")


def _layering(root: Path, files: dict[str, str], skip_rules: frozenset[str]) -> dict[str, tuple[str, tuple[str, ...]]]:
    origins: dict[str, tuple[str, tuple[str, ...]]] = {}
    for path in list(files):
        text = files.get(path)
        if text is None:
            continue
        inner = _rank(path)
        if inner is None:
            continue
        tree = _parsed(text)
        if tree is None:
            continue
        moved = False
        for node in tree.body if isinstance(tree, ast.Module) else []:
            if moved:
                break
            if not isinstance(node, ast.ImportFrom) or not node.module:
                continue
            resolved = resolve_from_module(path, node.module, node.level)
            if not resolved:
                continue
            outer_path = _module_path(files, resolved)
            if outer_path is None:
                continue
            outer = _rank(outer_path)
            if outer is None or outer <= inner:
                continue
            outer_text = files[outer_path]
            outer_tree = _parsed(outer_text)
            if outer_tree is None:
                continue
            for alias in node.names:
                fn = _function(outer_tree, alias.name)
                if fn is None or not _pure(fn):
                    continue
                moved_seg = ast.get_source_segment(outer_text, fn) or ""
                if not moved_seg:
                    continue
                home = _drop_imported_name(text, node.module, alias.name)
                home = _insert_block(home, moved_seg)
                away = _delete_function(outer_text, fn.name)
                if re.search(rf"\b{re.escape(alias.name)}\b", away):
                    away = _add_import(away, canonical_module(path), alias.name)
                applied = _commit(
                    root,
                    {path: text, outer_path: outer_text},
                    {path: home, outer_path: away},
                    "D6a.layering_violation",
                    skip_rules,
                    files=files,
                )
                if applied:
                    _merge_origins(origins, applied)
                    moved = True
                    break
    return origins


def _god_files(root: Path, files: dict[str, str], skip_rules: frozenset[str]) -> dict[str, tuple[str, tuple[str, ...]]]:
    origins: dict[str, tuple[str, tuple[str, ...]]] = {}
    for path in list(files):
        text = files.get(path)
        if text is None:
            continue
        if sum(1 for line in text.splitlines() if line.strip()) <= 500:
            continue
        tree = _parsed(text)
        if tree is None or not any(_route(node) for node in tree.body if isinstance(node, ast.FunctionDef)):
            continue
        moving = [
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef) and not node.decorator_list and _pure(node) and _sql_function(text, node)
        ]
        if len([node for node in tree.body if isinstance(node, ast.FunctionDef) and not _route(node)]) < 8 or not moving:
            continue
        stem = PurePosixPath(path).stem + "_db"
        sibling = str(PurePosixPath(path).with_name(stem + ".py"))
        blocks = [(ast.get_source_segment(text, node) or "") for node in moving]
        updated = text
        for node in moving:
            updated = _delete_function(updated, node.name)
        updated = _add_import(updated, canonical_module(sibling), ", ".join(node.name for node in moving))
        sibling_text = "\n\n".join(block for block in blocks if block) + "\n"
        _merge_origins(
            origins,
            _commit(
                root,
                {path: text, sibling: files.get(sibling, "")},
                {path: updated, sibling: sibling_text},
                "D6a.god_file",
                skip_rules,
                files=files,
            ),
        )
    return origins


def _sql_function(text: str, fn: ast.FunctionDef) -> bool:
    segment = ast.get_source_segment(text, fn) or ""
    return _SQL.search(segment) is not None


def _layer_folders(root: Path, files: dict[str, str], skip_rules: frozenset[str]) -> dict[str, tuple[str, tuple[str, ...]]]:
    origins: dict[str, tuple[str, tuple[str, ...]]] = {}
    all_py = {**_all_python(root), **files}
    for path in list(files):
        if path not in files:
            continue
        parts = PurePosixPath(path).parts
        if len(parts) < 2 or parts[-2] not in _LAYER_DIRS:
            continue
        old_module = canonical_module(path)
        if not old_module:
            continue
        all_importers = [
            other for other, text in all_py.items() if other != path and _references_module(other, text, old_module)
        ]
        prod_importers = [other for other in all_importers if not _is_test_path(other)]
        parents = {PurePosixPath(importer).parent for importer in prod_importers}
        if len(parents) != 1:
            continue
        importer_dir = parents.pop()
        if importer_dir.name in _LAYER_DIRS:
            continue
        destination = str(importer_dir / PurePosixPath(path).name) if str(importer_dir) != "." else PurePosixPath(path).name
        if destination == path or destination in all_py or (root / destination).exists():
            continue
        if any(_has_string_reference(text, old_module) for text in all_py.values()):
            continue
        known_mods = {canonical_module(p) for p in all_py if canonical_module(p)}
        moved_body, body_ok = _absolutize_internal_imports(path, files[path], known_mods)
        if not body_ok:
            continue
        new_module = canonical_module(destination)
        after: dict[str, str] = {destination: moved_body}
        before = {path: files[path], destination: ""}
        rewrite_ok = True
        for other in all_importers:
            text = all_py[other]
            rewritten = _rewrite_module_imports(other, text, old_module, new_module)
            if rewritten == text or _references_module(other, rewritten, old_module) or _parsed(rewritten) is None:
                rewrite_ok = False
                break
            after[other] = rewritten
            before[other] = text
        if not rewrite_ok:
            continue
        applied = _commit(root, before, after, "D6a.layer_folder", skip_rules, delete=frozenset({path}), files=files)
        if applied:
            _merge_origins(origins, applied)
            all_py.pop(path, None)
            for mod_path, mod_text in after.items():
                all_py[mod_path] = mod_text
    return origins


def _references_module(importer_path: str, text: str, target_module: str) -> bool:
    tree = _parsed(text)
    if tree is None:
        return _imports_module(text, target_module)
    target_parent, _, target_leaf = target_module.rpartition(".")
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == target_module or alias.name.startswith(target_module + "."):
                    return True
        elif isinstance(node, ast.ImportFrom):
            resolved = resolve_from_module(importer_path, node.module, node.level)
            if resolved is None:
                continue
            if resolved == target_module or resolved.startswith(target_module + "."):
                return True
            if resolved == target_parent and any(alias.name == target_leaf for alias in node.names):
                return True
    return False


def _has_string_reference(text: str, module: str) -> bool:
    tree = _parsed(text)
    if tree is None:
        return False
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if node.value == module or node.value.startswith(module + "."):
                return True
    return False


def _absolutize_internal_imports(path: str, text: str, known_mods: set[str]) -> tuple[str, bool]:
    tree = _parsed(text)
    if tree is None:
        return text, False
    rel_nodes = [node for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) and node.level > 0]
    if not rel_nodes:
        return text, True
    lines = text.splitlines()
    for node in sorted(rel_nodes, key=lambda n: n.lineno, reverse=True):
        resolved = resolve_from_module(path, node.module, node.level)
        if not resolved:
            return text, False
        if resolved not in known_mods and not any(m.startswith(resolved + ".") for m in known_mods):
            return text, False
        end = node.end_lineno or node.lineno
        indent = re.match(r"\s*", lines[node.lineno - 1]).group(0)
        rendered_names = ", ".join(
            f"{alias.name} as {alias.asname}" if alias.asname else alias.name for alias in node.names
        )
        replacement = f"{indent}from {resolved} import {rendered_names}"
        lines[node.lineno - 1 : end] = [replacement]
    rebuilt = "\n".join(lines) + ("\n" if text.endswith("\n") else "")
    return rebuilt, _parsed(rebuilt) is not None


def _rewrite_module_imports(importer_path: str, text: str, old_module: str, new_module: str) -> str:
    tree = _parsed(text)
    if tree is None:
        return _rewrite_module(text, old_module, new_module)
    old_parent, _, old_leaf = old_module.rpartition(".")
    new_parent, _, new_leaf = new_module.rpartition(".")
    matches: list[tuple[int, int, list[str]]] = []
    lines = text.splitlines()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            changed = False
            parts: list[str] = []
            for alias in node.names:
                if alias.name == old_module:
                    changed = True
                    asname = alias.asname or (old_module if "." not in old_module else None)
                    parts.append(f"{new_module} as {asname}" if asname else new_module)
                else:
                    parts.append(f"{alias.name} as {alias.asname}" if alias.asname else alias.name)
            if changed:
                indent = re.match(r"\s*", lines[node.lineno - 1]).group(0)
                matches.append((node.lineno, node.end_lineno or node.lineno, [f"{indent}import {', '.join(parts)}"]))
        elif isinstance(node, ast.ImportFrom):
            resolved = resolve_from_module(importer_path, node.module, node.level)
            if resolved is None:
                continue
            indent = re.match(r"\s*", lines[node.lineno - 1]).group(0)
            end = node.end_lineno or node.lineno
            if resolved == old_module:
                rendered = ", ".join(
                    f"{alias.name} as {alias.asname}" if alias.asname else alias.name for alias in node.names
                )
                matches.append((node.lineno, end, [f"{indent}from {new_module} import {rendered}"]))
            elif resolved == old_parent and any(alias.name == old_leaf for alias in node.names):
                kept = [a for a in node.names if a.name != old_leaf]
                moved = [a for a in node.names if a.name == old_leaf]
                new_lines: list[str] = []
                if kept:
                    kept_str = ", ".join(f"{a.name} as {a.asname}" if a.asname else a.name for a in kept)
                    new_lines.append(f"{indent}from {resolved} import {kept_str}")
                for a in moved:
                    target_as = a.asname or (old_leaf if new_leaf != old_leaf else None)
                    if new_parent:
                        rendered_leaf = f"{new_leaf} as {target_as}" if target_as else new_leaf
                        new_lines.append(f"{indent}from {new_parent} import {rendered_leaf}")
                    else:
                        rendered_leaf = f"{new_module} as {target_as}" if target_as else new_module
                        new_lines.append(f"{indent}import {rendered_leaf}")
                matches.append((node.lineno, end, new_lines))
    if not matches:
        return _rewrite_module(text, old_module, new_module)
    for start, end, repl in sorted(matches, key=lambda item: item[0], reverse=True):
        lines[start - 1 : end] = repl
    return "\n".join(lines) + ("\n" if text.endswith("\n") else "")


def _rank(path: str) -> int | None:
    pure = PurePosixPath(path)
    candidates = [*pure.parts[:-1], pure.stem]
    ranks = [_RANK[part] for part in candidates if part in _RANK]
    if not ranks:
        return None
    return min(ranks)


def _module_name(path: str) -> str:
    return canonical_module(path)


def _module_path(files: dict[str, str], module: str) -> str | None:
    candidate = module.replace(".", "/") + ".py"
    if candidate in files:
        return candidate
    init_candidate = module.replace(".", "/") + "/__init__.py"
    if init_candidate in files:
        return init_candidate
    return None


def _function(tree: ast.AST, name: str) -> ast.FunctionDef | None:
    for node in tree.body if isinstance(tree, ast.Module) else []:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    return None


def _pure(fn: ast.FunctionDef) -> bool:
    params = {arg.arg for arg in fn.args.args}
    for node in ast.walk(fn):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id not in params and node.id not in _BUILTINS:
            return False
    return True


def _key_is_mixed(text: str, key: str) -> bool:
    tree = _parsed(text)
    if tree is None:
        return True
    literals = 0
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and node.value == key:
            literals += 1
    return literals != len(_key_spans(tree, key))


def _key_spans(tree: ast.AST, key: str) -> list[tuple[int, int, int]]:
    spans: list[tuple[int, int, int]] = []

    class Walk(ast.NodeVisitor):
        def visit_Subscript(self, node: ast.Subscript) -> None:
            if isinstance(node.slice, ast.Constant) and node.slice.value == key:
                spans.append((node.slice.lineno, node.slice.col_offset, node.slice.end_col_offset or node.slice.col_offset))
            self.generic_visit(node)

        def visit_Dict(self, node: ast.Dict) -> None:
            for item in node.keys:
                if isinstance(item, ast.Constant) and item.value == key:
                    spans.append((item.lineno, item.col_offset, item.end_col_offset or item.col_offset))
            self.generic_visit(node)

        def visit_Call(self, node: ast.Call) -> None:
            func = node.func
            if (
                isinstance(func, ast.Attribute)
                and func.attr in {"get", "pop", "setdefault"}
                and node.args
                and isinstance(node.args[0], ast.Constant)
                and node.args[0].value == key
            ):
                arg = node.args[0]
                spans.append((arg.lineno, arg.col_offset, arg.end_col_offset or arg.col_offset))
            self.generic_visit(node)

    Walk().visit(tree)
    return spans


def _imports_module(text: str, module: str) -> bool:
    return f"from {module} import" in text or f"import {module}" in text or f"import {module} " in text


def _rewrite_module(text: str, old: str, new: str) -> str:
    text = text.replace(f"from {old} import", f"from {new} import")
    text = text.replace(f"import {old}", f"import {new}")
    old_parent, _, old_name = old.rpartition(".")
    new_parent, _, new_name = new.rpartition(".")
    if old_parent and old_name == new_name and new_parent:
        text = re.sub(
            rf"\bfrom {re.escape(old_parent)} import {re.escape(old_name)}\b",
            f"from {new_parent} import {new_name}",
            text,
        )
    return text


def _parsed(text: str) -> ast.AST | None:
    try:
        return ast.parse(text)
    except SyntaxError:
        return None


def _docstring(stmt: ast.stmt) -> bool:
    return isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant) and isinstance(stmt.value.value, str)


def _delete_function(text: str, name: str) -> str:
    tree = _parsed(text)
    if tree is None or not name:
        return text
    fn = _function(tree, name)
    if fn is None:
        return text
    start = fn.decorator_list[0].lineno if fn.decorator_list else fn.lineno
    end = fn.end_lineno or fn.lineno
    lines = text.splitlines()
    del lines[start - 1 : end]
    return "\n".join(lines) + ("\n" if text.endswith("\n") else "")


def _rename_calls(text: str, old: str, new: str) -> str:
    return re.sub(rf"\b{re.escape(old)}\s*\(", f"{new}(", text)


def _retarget_imports(text: str, old: str, new: str) -> str:
    return re.sub(rf"\bimport {re.escape(old)}\b", f"import {new}", text)


def _defining_module(text: str, path: str, target: str) -> str:
    tree = _parsed(text)
    if tree is None:
        return ""
    for node in tree.body if isinstance(tree, ast.Module) else []:
        if isinstance(node, ast.FunctionDef) and node.name == target:
            return canonical_module(path)
        if isinstance(node, ast.ImportFrom):
            resolved = resolve_from_module(path, node.module, node.level)
            if not resolved:
                continue
            for alias in node.names:
                if alias.asname == target or (alias.asname is None and alias.name == target):
                    return resolved
    return ""


def _imports_symbol_from(importer_path: str, text: str, target_module: str, name: str) -> bool:
    """Return True only when ``importer_path`` explicitly imports ``name`` from ``target_module``."""
    tree = _parsed(text)
    if tree is None:
        return False
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module != "__future__":
            resolved = resolve_from_module(importer_path, node.module, node.level)
            if resolved != target_module:
                continue
            for alias in node.names:
                if alias.name == name:
                    return True
    return False


def _has_unrewritable_symbol_ref(
    all_py: dict[str, str],
    source_path: str,
    source_module: str,
    name: str,
) -> bool:
    """Return True if any file in the repo references ``source_module.name`` via string patch, attribute, alias, or star import."""
    dotted = f"{source_module}.{name}"
    leaf_mod = source_module.rsplit(".", 1)[-1]
    for other, text in all_py.items():
        if dotted in text:
            return True
        if other == source_path:
            continue
        tree = _parsed(text)
        if tree is None:
            continue
        bound_module_aliases: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == source_module:
                        bound_module_aliases.add(alias.asname or alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom) and node.module != "__future__":
                resolved = resolve_from_module(other, node.module, node.level)
                if resolved == source_module:
                    for alias in node.names:
                        if alias.name == "*":
                            return True
                        if alias.name == name and alias.asname and alias.asname != name:
                            return True
                elif resolved and f"{resolved}.{leaf_mod}" == source_module:
                    for alias in node.names:
                        if alias.name == leaf_mod:
                            bound_module_aliases.add(alias.asname or alias.name)
        if bound_module_aliases:
            for node in ast.walk(tree):
                if isinstance(node, ast.Attribute) and node.attr == name:
                    if isinstance(node.value, ast.Name) and node.value.id in bound_module_aliases:
                        return True
                    if isinstance(node.value, ast.Attribute) and node.value.attr == leaf_mod:
                        return True
    return False


def _rename_ast_name_refs(text: str, old: str, new: str) -> str:
    """Rename AST ``Name(id=old)`` references while ignoring strings, comments, attributes, and shadowed locals."""
    tree = _parsed(text)
    if tree is None:
        return text
    spans: list[tuple[int, int, int]] = []

    class Renamer(ast.NodeVisitor):
        def __init__(self) -> None:
            self.shadow_depth = 0

        def _binds_old(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
            args = node.args
            params = [a.arg for a in (*args.posonlyargs, *args.args, *args.kwonlyargs)]
            if args.vararg:
                params.append(args.vararg.arg)
            if args.kwarg:
                params.append(args.kwarg.arg)
            if old in params:
                return True
            for child in ast.walk(node):
                if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store) and child.id == old:
                    return True
            return False

        def _visit_fn(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
            shadow = self._binds_old(node)
            if shadow:
                self.shadow_depth += 1
            for dec in node.decorator_list:
                self.visit(dec)
            for stmt in node.body:
                self.visit(stmt)
            if shadow:
                self.shadow_depth -= 1

        visit_FunctionDef = _visit_fn
        visit_AsyncFunctionDef = _visit_fn

        def visit_Name(self, node: ast.Name) -> None:
            if self.shadow_depth == 0 and node.id == old and isinstance(node.ctx, ast.Load):
                end_col = node.end_col_offset if node.end_col_offset is not None else node.col_offset + len(old)
                spans.append((node.lineno, node.col_offset, end_col))

    Renamer().visit(tree)
    if not spans:
        return text
    lines = text.splitlines(keepends=True)
    for lineno, col, end_col in sorted(spans, reverse=True):
        idx = lineno - 1
        if 0 <= idx < len(lines) and lines[idx][col:end_col] == old:
            lines[idx] = lines[idx][:col] + new + lines[idx][end_col:]
    return "".join(lines)


def _retarget_import_source(
    importer_path: str,
    text: str,
    old: str,
    new: str,
    old_module: str,
    new_module: str,
) -> str:
    pattern = re.compile(r"from (\S+) import \((.*?)\)|from (\S+) import ([^\n]+)", re.S)

    def _matches_old_module(source: str) -> bool:
        stripped = source.lstrip(".")
        level = len(source) - len(stripped)
        resolved = resolve_from_module(importer_path, stripped or None, level)
        return resolved == old_module

    def replace(match: re.Match[str]) -> str:
        source = match.group(1) or match.group(3)
        if not _matches_old_module(source):
            return match.group(0)
        raw = match.group(2) if match.group(1) else match.group(4)
        names = [item.strip() for item in raw.split(",") if item.strip()]
        kept: list[str] = []
        found = False
        for item in names:
            base = item.split(" as ")[0].strip()
            if base == old:
                found = True
                continue
            kept.append(item)
        if not found:
            return match.group(0)
        lines = [f"from {new_module} import {new}"]
        if kept and match.group(1):
            lines.append("from " + source + " import (\n    " + ",\n    ".join(kept) + ",\n)")
        elif kept:
            lines.append(f"from {source} import {', '.join(kept)}")
        return "\n".join(lines)

    return pattern.sub(replace, text)


def _preamble_insert_line(text: str) -> int:
    """Line index right after module header comments, docstring, and leading imports."""
    lines = text.splitlines()
    header_idx = 0
    while header_idx < len(lines) and (
        lines[header_idx].startswith("#!") or re.match(r"^#.*coding[:=]", lines[header_idx])
    ):
        header_idx += 1
    tree = _parsed(text)
    insert_at = header_idx
    if tree is not None and isinstance(tree, ast.Module):
        for idx, node in enumerate(tree.body):
            if idx == 0 and _docstring(node):
                insert_at = max(insert_at, node.end_lineno or node.lineno)
                continue
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                insert_at = max(insert_at, node.end_lineno or node.lineno)
                continue
            break
    return insert_at


def _add_import(text: str, module: str, name: str) -> str:
    line = f"from {module} import {name}"
    if line in text:
        return text
    insert_at = _preamble_insert_line(text)
    lines = text.splitlines()
    lines.insert(insert_at, line)
    return "\n".join(lines) + ("\n" if text.endswith("\n") else "")


def _insert_assign(text: str, line: str) -> str:
    if line in text:
        return text
    insert_at = _preamble_insert_line(text)
    lines = text.splitlines()
    lines.insert(insert_at, line)
    return "\n".join(lines) + ("\n" if text.endswith("\n") else "")


def _insert_block(text: str, block: str) -> str:
    if block.strip() in text:
        return text
    return text.rstrip() + "\n\n" + block.strip() + "\n"


def _drop_imported_name(text: str, module: str, name: str) -> str:
    pattern = re.compile(rf"from \.*{re.escape(module)} import ([^\n]+)")

    def replace(match: re.Match[str]) -> str:
        names = [item.strip() for item in match.group(1).split(",") if item.strip() and item.strip() != name]
        if not names:
            return ""
        return match.group(0).split(" import ")[0] + f" import {', '.join(names)}"

    return pattern.sub(replace, text, count=1)
