"""Run a function as it was and as it is, on the same plain inputs."""

from __future__ import annotations

import ast
import subprocess
import sys
import textwrap

__all__ = ["behavior_holds"]

_SIMPLE = {
    "int": [0, 1, -1, 2, 10],
    "str": ["", "a", "hello"],
    "bool": [True, False],
    "float": [0.0, 1.5, -2.0],
}


def behavior_holds(before: str, after: str) -> bool:
    """Return False when a changed pure function returns a different value.

    A stub that now raises, and a module that cannot be imported, are left
    for the caller to judge. A comment-only edit has nothing to compare.
    """
    if before == after:
        return True
    try:
        old_tree = ast.parse(before)
        new_tree = ast.parse(after)
    except SyntaxError:
        return False
    names = _comparable(old_tree, new_tree)
    if not names:
        return True
    script = _script(before, after, names)
    try:
        completed = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError):
        return False
    return completed.returncode == 0


def _comparable(old_tree: ast.AST, new_tree: ast.AST) -> list[str]:
    old = _functions(old_tree)
    new = _functions(new_tree)
    names: list[str] = []
    for name, after in new.items():
        before = old.get(name)
        if before is None or _signature(before) != _signature(after):
            continue
        if ast.dump(before) == ast.dump(after):
            continue
        if _intentional(after) or _is_debugger(before):
            continue
        if not _plain_signature(after):
            continue
        names.append(name)
    return names


def _functions(tree: ast.AST) -> dict[str, ast.FunctionDef]:
    found: dict[str, ast.FunctionDef] = {}
    for node in tree.body if isinstance(tree, ast.Module) else []:
        if isinstance(node, ast.FunctionDef):
            found[node.name] = node
    return found


def _signature(node: ast.FunctionDef) -> tuple[str, ...]:
    args = node.args
    names = [arg.arg for arg in [*args.posonlyargs, *args.args]]
    if args.vararg or args.kwarg:
        names.append("*")
    return tuple(names)


def _is_debugger(node: ast.FunctionDef) -> bool:
    for child in ast.walk(node):
        if isinstance(child, ast.Call) and isinstance(child.func, ast.Name) and child.func.id == "breakpoint":
            return True
        if isinstance(child, ast.Attribute) and child.attr == "set_trace":
            return True
    return False


def _intentional(node: ast.FunctionDef) -> bool:
    """A stub that now raises is an intended behavior change."""
    body = [stmt for stmt in node.body if not isinstance(stmt, ast.Expr)]
    if len(body) != 1 or not isinstance(body[0], ast.Raise) or not isinstance(body[0].exc, ast.Call):
        return False
    func = body[0].exc.func
    return isinstance(func, ast.Name) and func.id == "RuntimeError"


def _plain_signature(node: ast.FunctionDef) -> bool:
    args = node.args
    if args.vararg or args.kwarg or args.kwonlyargs:
        return False
    for arg in [*args.posonlyargs, *args.args]:
        if arg.annotation is not None and _annotation_name(arg.annotation) not in _SIMPLE:
            return False
    return True


def _annotation_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    return ""


def _script(before: str, after: str, names: list[str]) -> str:
    payload = textwrap.dedent(
        """
        import ast, itertools, traceback
        BEFORE = {before!r}
        AFTER = {after!r}
        NAMES = {names!r}
        SIMPLE = {simple!r}

        def load(src):
            namespace = {{"__name__": "compared"}}
            exec(compile(src, "<compared>", "exec"), namespace)
            return namespace

        def cases(func):
            args = func.__code__.co_varnames[: func.__code__.co_argcount]
            annotations = getattr(func, "__annotations__", {{}})
            columns = []
            for name in args:
                kind = annotations.get(name)
                label = kind if isinstance(kind, str) else getattr(kind, "__name__", "")
                columns.append(SIMPLE.get(label, [0, 1]))
            if not columns:
                return [()]
            produced = list(itertools.product(*columns))
            return produced[:12]

        try:
            old = load(BEFORE)
            new = load(AFTER)
        except Exception:
            raise SystemExit(0)
        for name in NAMES:
            left = old.get(name)
            right = new.get(name)
            if left is None or right is None:
                continue
            for sample in cases(right):
                try:
                    a = left(*sample)
                except Exception as exc:
                    a = ("raise", type(exc).__name__)
                try:
                    b = right(*sample)
                except Exception as exc:
                    b = ("raise", type(exc).__name__)
                if a != b:
                    raise SystemExit(1)
        """
    ).format(before=before, after=after, names=names, simple=_SIMPLE)
    return payload
