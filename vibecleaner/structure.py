"""Rewrite the nine structural slop indicators.

Each repair is a behavior-preserving edit a second run does not repeat.
A high-risk file is left untouched.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path, PurePosixPath

from vibecleaner.behavior import behavior_holds
from vibecleaner.collector import collect
from vibecleaner.deslop import _is_test_path
from vibecleaner.models import Language
from vibecleaner.risk import RiskTier, classify_file

_LAYER_DIRS = frozenset({"utils", "helpers", "services", "controllers", "repositories"})
_RANK = {
    "models": 0,
    "domain": 0,
    "entities": 0,
    "repositories": 1,
    "repository": 1,
    "db": 1,
    "services": 2,
    "service": 2,
    "controllers": 3,
    "controller": 3,
    "routes": 3,
    "api": 3,
    "views": 3,
    "handlers": 3,
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
        "status_code",
    }
)
_ROUTE_VERBS = frozenset({"get", "post", "put", "patch", "delete"})
_SQL = re.compile(r"\b(?:SELECT|INSERT|UPDATE|DELETE)\b")


def repair_structure(root: Path, skip_rules: frozenset[str] = frozenset()) -> dict[str, tuple[str, tuple[str, ...]]]:
    """Apply every structural repair under ``root``. Return the originals that changed."""
    origins: dict[str, tuple[str, tuple[str, ...]]] = {}
    for _ in range(4):
        batch = _once(root, skip_rules)
        if not batch:
            break
        for path, (original, rules) in batch.items():
            if path not in origins:
                origins[path] = (original, rules)
            else:
                previous, previous_rules = origins[path]
                origins[path] = (previous, tuple(dict.fromkeys((*previous_rules, *rules))))
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
        origins.update(repair(root, files, skip_rules))
        files = _python(root)
    origins.update(_script_boundary(root, skip_rules))
    return origins


def _python(root: Path) -> dict[str, str]:
    found: dict[str, str] = {}
    for source in collect(root).files:
        if source.language != Language.PYTHON or _is_test_path(source.path):
            continue
        found[source.path] = source.text
    return found


def _commit(
    root: Path,
    before: dict[str, str],
    after: dict[str, str],
    rule: str,
    skip_rules: frozenset[str],
    delete: frozenset[str] = frozenset(),
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
        if path.endswith(".py") and path in before and path in changed and not behavior_holds(before[path], changed[path]):
            return {}
    origins: dict[str, tuple[str, tuple[str, ...]]] = {}
    for path, text in changed.items():
        destination = root / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(text, encoding="utf-8")
        origins[path] = (before.get(path, ""), (rule,))
    for path in delete:
        destination = root / path
        if destination.is_file():
            destination.unlink()
        if path not in origins:
            origins[path] = (before.get(path, ""), (rule,))
    return origins


def _passthroughs(root: Path, files: dict[str, str], skip_rules: frozenset[str]) -> dict[str, tuple[str, tuple[str, ...]]]:
    origins: dict[str, tuple[str, tuple[str, ...]]] = {}
    for path, text in files.items():
        tree = _parsed(text)
        if tree is None:
            continue
        wrappers = _wrapper_map(tree)
        if not wrappers:
            continue
        updated = text
        external: dict[str, str] = {}
        for name, target in wrappers.items():
            importers = {
                other: source
                for other, source in files.items()
                if other != path and _imports_name(source, name)
            }
            if not name.startswith("_") and not importers and not _calls_name(tree, name):
                continue
            home = _defining_module(text, path, target)
            if importers and not home:
                continue
            updated = _delete_function(updated, name)
            updated = _rename_calls(updated, name, target)
            updated = _retarget_imports(updated, name, target)
            updated = re.sub(rf"""["']{re.escape(name)}["']\s*,?\s*""", "", updated)
            for other, source in importers.items():
                retargeted = _retarget_import_source(source, name, target, home)
                retargeted = re.sub(rf"(?<!def )\b{re.escape(name)}\b", target, retargeted)
                external[other] = retargeted
        after = {path: updated, **external}
        before = {path: text, **{other: files[other] for other in external}}
        origins.update(_commit(root, before, after, "D6a.passthrough_wrapper", skip_rules))
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
        module = _module_name(keeper_path)
        for path, fn in ordered[1:]:
            if path == keeper_path and fn.name == keeper.name:
                continue
            text = (root / path).read_text(encoding="utf-8")
            updated = _delete_function(text, fn.name)
            if path != keeper_path:
                imported = keeper.name if fn.name == keeper.name else f"{keeper.name} as {fn.name}"
                updated = _add_import(updated, module, imported)
            elif fn.name != keeper.name:
                updated = _rename_calls(updated, fn.name, keeper.name)
            origins.update(_commit(root, {path: text}, {path: updated}, rule, skip_rules))
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
    for path, text in files.items():
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
            origins.update(_commit(root, {path: text}, {path: updated}, "D6a.illegal_state", skip_rules))
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
    for path, text in files.items():
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
            origins.update(_commit(root, {path: text}, {path: updated}, "D9.boundary_schema", skip_rules))
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
        unique = list(dict.fromkeys(paths))
        if not 2 <= len(unique) <= 4 or any(_key_is_mixed(files[path], key) for path in unique):
            continue
        const = key.upper()
        home = unique[0]
        home_module = _module_name(home)
        if any(
            _imports_module(files[home], _module_name(path)) or _imports_module(files[path], home_module)
            for path in unique
            if path != home
        ):
            continue
        after: dict[str, str] = {}
        before = {path: files[path] for path in unique}
        for path in unique:
            updated = _replace_key(files[path], key, const)
            if path == home:
                updated = _insert_assign(updated, f'{const} = "{key}"')
            else:
                updated = _add_import(updated, _module_name(home), const)
            after[path] = updated
        origins.update(_commit(root, before, after, "D6a.implicit_coupling", skip_rules))
    return origins


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
    lines = text.splitlines()
    for lineno, start, end in sorted(spans, reverse=True):
        row = lines[lineno - 1]
        lines[lineno - 1] = row[:start] + const + row[end:]
    return "\n".join(lines) + ("\n" if text.endswith("\n") else "")


def _layering(root: Path, files: dict[str, str], skip_rules: frozenset[str]) -> dict[str, tuple[str, tuple[str, ...]]]:
    origins: dict[str, tuple[str, tuple[str, ...]]] = {}
    for path, text in files.items():
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
            outer_path = _module_path(files, node.module)
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
                moved = ast.get_source_segment(outer_text, fn) or ""
                if not moved:
                    continue
                home = _drop_imported_name(text, node.module, alias.name)
                home = _insert_block(home, moved)
                away = _delete_function(outer_text, fn.name)
                if re.search(rf"\b{re.escape(alias.name)}\b", away):
                    away = _add_import(away, _module_name(path), alias.name)
                applied = _commit(
                    root,
                    {path: text, outer_path: outer_text},
                    {path: home, outer_path: away},
                    "D6a.layering_violation",
                    skip_rules,
                )
                if applied:
                    origins.update(applied)
                    files[path] = (root / path).read_text(encoding="utf-8")
                    if (root / outer_path).is_file():
                        files[outer_path] = (root / outer_path).read_text(encoding="utf-8")
                    moved = True
                    break
    return origins


def _god_files(root: Path, files: dict[str, str], skip_rules: frozenset[str]) -> dict[str, tuple[str, tuple[str, ...]]]:
    origins: dict[str, tuple[str, tuple[str, ...]]] = {}
    for path, text in files.items():
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
        updated = _add_import(updated, _module_name(sibling), ", ".join(node.name for node in moving))
        sibling_text = "\n\n".join(block for block in blocks if block) + "\n"
        origins.update(
            _commit(
                root,
                {path: text, sibling: files.get(sibling, "")},
                {path: updated, sibling: sibling_text},
                "D6a.god_file",
                skip_rules,
            )
        )
    return origins


def _sql_function(text: str, fn: ast.FunctionDef) -> bool:
    segment = ast.get_source_segment(text, fn) or ""
    return _SQL.search(segment) is not None


def _layer_folders(root: Path, files: dict[str, str], skip_rules: frozenset[str]) -> dict[str, tuple[str, tuple[str, ...]]]:
    origins: dict[str, tuple[str, tuple[str, ...]]] = {}
    for path in list(files):
        parts = PurePosixPath(path).parts
        if len(parts) < 2 or parts[-2] not in _LAYER_DIRS:
            continue
        importers = [other for other, text in files.items() if other != path and _imports_module(text, _module_name(path))]
        parents = {PurePosixPath(importer).parent for importer in importers}
        if len(parents) != 1:
            continue
        importer_dir = parents.pop()
        if importer_dir.name in _LAYER_DIRS:
            continue
        destination = str(importer_dir / PurePosixPath(path).name) if str(importer_dir) != "." else PurePosixPath(path).name
        if destination == path or destination in files:
            continue
        old_module = _module_name(path)
        new_module = _module_name(destination)
        after: dict[str, str] = {destination: files[path]}
        before = {path: files[path], destination: ""}
        for other, text in files.items():
            if other == path:
                continue
            rewritten = _rewrite_module(text, old_module, new_module)
            if rewritten != text:
                after[other] = rewritten
                before[other] = text
        origins.update(_commit(root, before, after, "D6a.layer_folder", skip_rules, delete=frozenset({path})))
    return origins


def _rank(path: str) -> int | None:
    ranks = [_RANK[part] for part in PurePosixPath(path).parts if part in _RANK]
    if not ranks:
        return None
    return min(ranks)


def _module_name(path: str) -> str:
    pure = PurePosixPath(path)
    if pure.suffix:
        pure = pure.with_suffix("")
    return ".".join(pure.parts)


def _module_path(files: dict[str, str], module: str) -> str | None:
    candidate = module.replace(".", "/") + ".py"
    if candidate in files:
        return candidate
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


def _imports_name(text: str, name: str) -> bool:
    tree = _parsed(text)
    if tree is None:
        return False
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                if alias.name == name or alias.asname == name:
                    return True
    return False


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
            return _module_name(path)
        if isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            for alias in node.names:
                if alias.asname == target or (alias.asname is None and alias.name == target):
                    return node.module
    return ""


def _retarget_import_source(text: str, old: str, new: str, module: str) -> str:
    pattern = re.compile(r"from (\S+) import \((.*?)\)|from (\S+) import ([^\n]+)", re.S)

    def replace(match: re.Match[str]) -> str:
        source = match.group(1) or match.group(3)
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
        lines = [f"from {module} import {new}"]
        if kept and match.group(1):
            lines.append("from " + source + " import (\n    " + ",\n    ".join(kept) + ",\n)")
        elif kept:
            lines.append(f"from {source} import {', '.join(kept)}")
        return "\n".join(lines)

    return pattern.sub(replace, text)


def _add_import(text: str, module: str, name: str) -> str:
    line = f"from {module} import {name}"
    if line in text:
        return text
    tree = _parsed(text)
    insert_at = 0
    if tree is not None:
        for node in tree.body if isinstance(tree, ast.Module) else []:
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                insert_at = node.end_lineno or node.lineno
    lines = text.splitlines()
    lines.insert(insert_at, line)
    return "\n".join(lines) + ("\n" if text.endswith("\n") else "")


def _insert_assign(text: str, line: str) -> str:
    if line in text:
        return text
    return _add_import(text, "__unused__", "__unused__").replace("from __unused__ import __unused__", line)


def _insert_block(text: str, block: str) -> str:
    if block.strip() in text:
        return text
    return text.rstrip() + "\n\n" + block.strip() + "\n"


def _drop_imported_name(text: str, module: str, name: str) -> str:
    pattern = re.compile(rf"from {re.escape(module)} import ([^\n]+)")

    def replace(match: re.Match[str]) -> str:
        names = [item.strip() for item in match.group(1).split(",") if item.strip() and item.strip() != name]
        if not names:
            return ""
        return f"from {module} import {', '.join(names)}"

    return pattern.sub(replace, text, count=1)
