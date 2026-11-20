"""Public function and method signatures, from tree-sitter."""

from __future__ import annotations

import json
from dataclasses import dataclass

from tree_sitter import Node

from vibeguard.models import Language
from vibeguard.ts_parse import decorator_leaf, node_text
from vibeguard.verify.files import line_of, parsed

@dataclass(frozen=True)
class Param:
    name: str
    kind: str  # "pos", "kw", "var", "varkw"
    required: bool


def encode_params(params: tuple[Param, ...]) -> str:
    payload = [{"n": param.name, "k": param.kind, "r": param.required} for param in params]
    return json.dumps(payload, separators=(",", ":"))


def decode_params(text: str) -> tuple[Param, ...]:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return ()
    if not isinstance(payload, list):
        return ()
    params: list[Param] = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        name = item.get("n")
        kind = item.get("k")
        if not isinstance(name, str) or not isinstance(kind, str):
            continue
        params.append(Param(name, kind, bool(item.get("r"))))
    return tuple(params)


def signature_changed(old: str, new: str) -> bool:
    """True when a public signature breaks callers.

    Appending optional parameters keeps the previous prefix and is allowed.
    Removing, reordering, or renaming a parameter is not, and neither is
    adding a required parameter or turning an optional one into a required one.
    """
    previous = decode_params(old)
    current = list(decode_params(new))
    while len(current) > len(previous) and _trailing_compatible(current[-1]):
        current.pop()
    if len(current) != len(previous):
        return True
    for before, after in zip(previous, current):
        if before.name != after.name or before.kind != after.kind:
            return True
        if not before.required and after.required:
            return True
    return False


def _trailing_compatible(param: Param) -> bool:
    if param.kind in {"var", "varkw"}:
        return True
    return not param.required and param.kind in {"pos", "kw"}


def signature_index(rel: str, text: str) -> dict[str, tuple[str, int]]:
    """Map ``path:qualname`` to ``(encoded params, line)`` for public callables."""
    loaded = parsed(rel, text)
    if loaded is None:
        return {}
    source, root = loaded
    if source.language == Language.PYTHON:
        found = _python_index(root)
    else:
        found = _script_index(root)
    return {f"{rel}:{qualname}": (encoded, line) for qualname, (encoded, line) in found.items()}


def iter_functions(root: Node) -> list[tuple[str, Node]]:
    """Qualified name and function node, outermost first, including methods."""
    found: list[tuple[str, Node]] = []
    _collect_functions(root, "", found)
    return found


def function_params(func: Node) -> set[str]:
    names = {param.name for param in _params_of(func) if param.kind in {"pos", "kw"}}
    if func.type in {"function_definition", "method_definition"}:
        names.discard("self")
        names.discard("cls")
    return names


def _python_index(root: Node) -> dict[str, tuple[str, int]]:
    found: dict[str, tuple[str, int]] = {}
    for child in root.named_children:
        target = _definition(child)
        if target.type == "function_definition":
            _add_function(found, "", target, _python_params(target))
        elif target.type == "class_definition":
            _add_class(found, target)
    return found


def _add_class(found: dict[str, tuple[str, int]], cls: Node) -> None:
    name_node = cls.child_by_field_name("name")
    if name_node is None or not _public(node_text(name_node)):
        return
    class_name = node_text(name_node)
    body = cls.child_by_field_name("body")
    if body is None:
        return
    for child in body.named_children:
        target = _definition(child)
        if target.type != "function_definition":
            continue
        method = target.child_by_field_name("name")
        if method is None or not _public(node_text(method)):
            continue
        leaves = _decorator_leaves(child)
        params = _python_params(target)
        if "staticmethod" not in leaves and params and params[0].name in {"self", "cls"}:
            params = params[1:]
        _add_function(found, class_name, target, params)


def _add_function(found: dict[str, tuple[str, int]], owner: str, func: Node, params: tuple[Param, ...]) -> None:
    name_node = func.child_by_field_name("name")
    if name_node is None:
        return
    name = node_text(name_node)
    if not owner and not _public(name):
        return
    qualname = f"{owner}.{name}" if owner else name
    found[qualname] = (encode_params(params), line_of(func))


def _python_params(func: Node) -> tuple[Param, ...]:
    parameters = func.child_by_field_name("parameters")
    if parameters is None:
        return ()
    kind = "pos"
    params: list[Param] = []
    for child in parameters.children:
        if child.type == "keyword_separator":
            if node_text(child) == "*":
                kind = "kw"
            continue
        if child.type in {"identifier", "typed_parameter"}:
            params.append(Param(_first_identifier(child), kind, True))
        elif child.type in {"default_parameter", "typed_default_parameter"}:
            params.append(Param(_first_identifier(child), kind, False))
        elif child.type in {"list_splat_pattern", "list_splat"}:
            params.append(Param(_first_identifier(child) or "args", "var", False))
            kind = "kw"
        elif child.type in {"dictionary_splat_pattern", "dictionary_splat"}:
            params.append(Param(_first_identifier(child) or "kwargs", "varkw", False))
    return tuple(params)


def _script_index(root: Node) -> dict[str, tuple[str, int]]:
    found: dict[str, tuple[str, int]] = {}
    for child in root.named_children:
        _script_statement(found, child)
    return found


def _script_statement(found: dict[str, tuple[str, int]], node: Node) -> None:
    if node.type == "function_declaration":
        _add_script_function(found, "", node)
        return
    if node.type == "class_declaration":
        _add_script_class(found, node)
        return
    if node.type == "export_statement":
        for child in node.named_children:
            if child.type == "function_declaration":
                _add_script_function(found, "", child)
            elif child.type == "class_declaration":
                _add_script_class(found, child)
            elif child.type == "lexical_declaration":
                _add_script_arrows(found, child)
        return
    if node.type == "lexical_declaration":
        _add_script_arrows(found, node)


def _add_script_class(found: dict[str, tuple[str, int]], cls: Node) -> None:
    name_node = cls.child_by_field_name("name")
    if name_node is None or not _public(node_text(name_node)):
        return
    body = cls.child_by_field_name("body")
    if body is None:
        return
    class_name = node_text(name_node)
    for child in body.named_children:
        if child.type != "method_definition" or _script_private(child):
            continue
        _add_script_function(found, class_name, child)


def _add_script_arrows(found: dict[str, tuple[str, int]], lexical: Node) -> None:
    for declarator in lexical.named_children:
        if declarator.type != "variable_declarator":
            continue
        name_node = declarator.child_by_field_name("name")
        value = declarator.child_by_field_name("value")
        if name_node is None or value is None or not _public(node_text(name_node)):
            continue
        if value.type not in {"arrow_function", "function_expression"}:
            continue
        params = _script_params(value)
        found[node_text(name_node)] = (encode_params(params), line_of(declarator))


def _add_script_function(found: dict[str, tuple[str, int]], owner: str, func: Node) -> None:
    name_node = func.child_by_field_name("name")
    if name_node is None or _script_private(func):
        return
    name = node_text(name_node)
    if not _public(name):
        return
    qualname = f"{owner}.{name}" if owner else name
    found[qualname] = (encode_params(_script_params(func)), line_of(func))


def _script_params(func: Node) -> tuple[Param, ...]:
    parameters = func.child_by_field_name("parameters")
    if parameters is None:
        return ()
    if parameters.type == "identifier":
        return (Param(node_text(parameters), "pos", True),)
    params: list[Param] = []
    for child in parameters.named_children:
        if child.type not in {"required_parameter", "optional_parameter"}:
            continue
        name, kind = _script_param_name(child)
        if name == "this":
            continue
        required = child.type == "required_parameter" and not any(part.type == "=" for part in child.children)
        params.append(Param(name, kind, required))
    return tuple(params)


def _script_param_name(node: Node) -> tuple[str, str]:
    for child in node.named_children:
        if child.type == "rest_pattern":
            ident = next((part for part in child.named_children if part.type == "identifier"), None)
            return (node_text(ident) if ident is not None else "rest", "var")
        if child.type == "identifier":
            return node_text(child), "pos"
    return "?", "pos"


def _script_private(node: Node) -> bool:
    for child in node.children:
        if child.type == "accessibility_modifier" and node_text(child) in {"private", "protected"}:
            return True
    name_node = node.child_by_field_name("name")
    return name_node is not None and node_text(name_node).startswith("#")


def _params_of(func: Node) -> tuple[Param, ...]:
    if func.type == "function_definition":
        return _python_params(func)
    return _script_params(func)


def _collect_functions(node: Node, prefix: str, found: list[tuple[str, Node]]) -> None:
    for child in node.named_children:
        target = _definition(child)
        if target.type in {"function_definition", "function_declaration", "method_definition"}:
            name_node = target.child_by_field_name("name")
            name = node_text(name_node) if name_node is not None else ""
            qualname = f"{prefix}.{name}" if prefix and name else name or prefix
            found.append((qualname, target))
            body = target.child_by_field_name("body")
            if body is not None:
                _collect_functions(body, qualname, found)
        elif target.type in {"class_definition", "class_declaration"}:
            name_node = target.child_by_field_name("name")
            name = node_text(name_node) if name_node is not None else ""
            qualname = f"{prefix}.{name}" if prefix and name else name
            body = target.child_by_field_name("body")
            if body is not None:
                _collect_functions(body, qualname, found)
        elif target.type == "export_statement":
            _collect_functions(target, prefix, found)


def _definition(node: Node) -> Node:
    if node.type != "decorated_definition":
        return node
    definition = node.child_by_field_name("definition")
    return definition if definition is not None else node


def _decorator_leaves(node: Node) -> set[str]:
    if node.type != "decorated_definition":
        return set()
    return {decorator_leaf(child) for child in node.named_children if child.type == "decorator"}


def _first_identifier(node: Node) -> str:
    if node.type == "identifier":
        return node_text(node)
    named = node.child_by_field_name("name")
    if named is not None:
        return node_text(named)
    for child in node.named_children:
        if child.type == "identifier":
            return node_text(child)
    return ""


def _public(name: str) -> bool:
    if name.startswith("__") and name.endswith("__"):
        return True
    return not name.startswith("_")

