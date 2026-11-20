"""Readers for the project files gate detection and the tamper guard compare."""

from __future__ import annotations

import configparser
import json
import re

try:
    import tomllib
except ImportError:  # Python 3.10
    tomllib = None

_REQ_NAME = re.compile(r"^\s*([A-Za-z0-9_.\-]+)")
_HASH_COMMENT = re.compile(r"(?m)//.*?$")
_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
_TRAILING_COMMA = re.compile(r",(\s*[}\]])")


def load_toml(text: str) -> dict[str, object]:
    if tomllib is not None:
        try:
            loaded = tomllib.loads(text)
        except tomllib.TOMLDecodeError:
            return {}
        return loaded if isinstance(loaded, dict) else {}
    return basic_toml(text)


def basic_toml(text: str) -> dict[str, object]:
    """Subset of TOML: tables, scalars, and arrays of scalars. Used on Python 3.10."""
    root: dict[str, object] = {}
    current = root
    lines = text.splitlines()
    index = 0
    while index < len(lines):
        raw = _strip_inline_comment(lines[index].strip())
        if not raw or raw.startswith("#"):
            index += 1
            continue
        if raw.startswith("[["):
            index += 1
            continue
        if raw.startswith("[") and raw.endswith("]"):
            current = _ensure_table(root, raw[1:-1].strip())
            index += 1
            continue
        if "=" not in raw:
            index += 1
            continue
        key, value = raw.split("=", 1)
        parsed, consumed = _parse_value(value.strip(), lines, index)
        current[key.strip().strip("\"'")] = parsed
        index += consumed
    return root


def load_json(text: str) -> dict[str, object]:
    stripped = _TRAILING_COMMA.sub(r"\1", _HASH_COMMENT.sub("", _BLOCK_COMMENT.sub("", text)))
    try:
        loaded = json.loads(stripped)
    except json.JSONDecodeError:
        return {}
    return loaded if isinstance(loaded, dict) else {}


def load_ini(text: str) -> configparser.RawConfigParser:
    parser = configparser.RawConfigParser()
    try:
        parser.read_string(text)
    except configparser.Error:
        return configparser.RawConfigParser()
    return parser


def dig(data: object, *keys: str) -> object:
    current = data
    for key in keys:
        if not isinstance(current, dict) or key not in current:
            return None
        current = current[key]
    return current


def requirement_name(spec: str) -> str:
    spec = spec.split(";", 1)[0].strip()
    spec = spec.split("[", 1)[0]
    match = _REQ_NAME.match(spec)
    if match is None:
        return ""
    return match.group(1).lower().replace("_", "-")


def requirement_names(text: str) -> set[str]:
    names: set[str] = set()
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith(("-", ".")):
            continue
        name = requirement_name(line)
        if name:
            names.add(name)
    return names


def _ensure_table(root: dict[str, object], name: str) -> dict[str, object]:
    current = root
    for part in name.split("."):
        part = part.strip().strip("\"'")
        nxt = current.get(part)
        if not isinstance(nxt, dict):
            nxt = {}
            current[part] = nxt
        current = nxt
    return current


def _parse_value(value: str, lines: list[str], index: int) -> tuple[object, int]:
    if value.startswith("["):
        blob, consumed = _collect(value, lines, index, "[", "]")
        return _parse_array(blob[1:-1]), consumed
    return _parse_scalar(value), 1


def _collect(value: str, lines: list[str], index: int, open_ch: str, close_ch: str) -> tuple[str, int]:
    blob = value
    consumed = 1
    while blob.count(open_ch) > blob.count(close_ch) and index + consumed < len(lines):
        blob = f"{blob}\n{_strip_inline_comment(lines[index + consumed])}"
        consumed += 1
    return blob, consumed


def _parse_array(inner: str) -> list[object]:
    items: list[object] = []
    buf: list[str] = []
    quote = ""
    for char in inner:
        if char in {"'", '"'} and not quote:
            quote = char
            buf.append(char)
            continue
        if quote and char == quote:
            quote = ""
            buf.append(char)
            continue
        if char == "," and not quote:
            item = "".join(buf).strip()
            if item:
                items.append(_parse_scalar(item))
            buf = []
            continue
        buf.append(char)
    item = "".join(buf).strip()
    if item:
        items.append(_parse_scalar(item))
    return items


def _parse_scalar(value: str) -> object:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    if value == "true":
        return True
    if value == "false":
        return False
    try:
        if "." in value:
            return float(value)
        return int(value)
    except ValueError:
        return value


def _strip_inline_comment(value: str) -> str:
    quote = ""
    for index, char in enumerate(value):
        if char in {"'", '"'} and not quote:
            quote = char
            continue
        if quote and char == quote:
            quote = ""
            continue
        if char == "#" and not quote:
            return value[:index].strip()
    return value.strip()
