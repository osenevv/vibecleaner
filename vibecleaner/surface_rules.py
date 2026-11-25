"""Rewrite the AI surface tells from a design-rules list.

Each function removes one tell. A second pass leaves the file alone.
"""

from __future__ import annotations

import re

_HEX = re.compile(r"#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})\b")
_CLASS = re.compile(r"""(\bclass\s*=\s*)(['"])([^'"]*)\2""", re.I)
_STYLE_ATTR = re.compile(r"""(\bstyle\s*=\s*)(['"])(.*?)\2""", re.I | re.S)
_STYLE_TAG = re.compile(r"(<style\b[^>]*>)(.*?)(</style>)", re.I | re.S)
_EYEBROW = re.compile(
    r"<(p|span|div|label)\b[^>]*\bclass\s*=\s*(['\"])[^'\"]*\b(?:eyebrow|kicker|overline)\b[^'\"]*\2[^>]*>.*?</\1>",
    re.I | re.S,
)
_PILL = re.compile(
    r"<(span|div)\b[^>]*\bclass\s*=\s*(['\"])[^'\"]*\b(?:pill|badge|chip)\b[^'\"]*\2[^>]*>.*?</\1>",
    re.I | re.S,
)
_TEXT = re.compile(r"(<(?:h[1-6]|button|a|p|span|label|li)\b[^>]*>)([^<]+)(</)", re.I)
_ICON = re.compile(r"<(\w+)\b([^>]*)>([^<]*)</\1>", re.I)
_TAG = re.compile(r"</(\w+)\s*>|<(\w+)\b([^>]*)>", re.I)
_CLASS_VALUE = re.compile(r"""class\s*=\s*(['"])(.*?)\1""", re.I)
_FLOAT = re.compile(r"\b(?:dialog|popover|menu|tooltip|modal|overlay)\b", re.I)
_POSITION = re.compile(r"position\s*:\s*(?:fixed|absolute|sticky)", re.I)
_TEMPLATE_EXPR = re.compile(r"\{\{|\{%|<%|\$\{")
_GRADIENT = ("linear-gradient", "radial-gradient", "repeating-linear-gradient")
_MOTION_PROPS = frozenset(
    {
        "transition",
        "animation",
        "transition-duration",
        "animation-duration",
        "animation-timing-function",
        "transition-timing-function",
    }
)
_ROOT = """:root {
  --background: oklch(0.97 0.003 106);
  --surface: oklch(1 0 0);
  --foreground: oklch(0.23 0 0);
  --text-secondary: oklch(0.48 0 0);
  --border: oklch(0.91 0.005 106);
  --accent: oklch(0.23 0 0);
}
"""
_CHECKS = """<style data-vibecleaner="design">
:root {
  --background: oklch(0.97 0.003 106);
  --surface: oklch(1 0 0);
  --foreground: oklch(0.23 0 0);
  --text-secondary: oklch(0.48 0 0);
  --border: oklch(0.91 0.005 106);
  --accent: oklch(0.23 0 0);
}
@media (max-width: 390px) {
  img, svg, video { max-width: 100%; height: auto; }
}
@media (prefers-color-scheme: dark) {
  :root {
    --background: oklch(0.19 0 0);
    --surface: oklch(0.23 0 0);
    --foreground: oklch(0.97 0 0);
    --text-secondary: oklch(0.80 0 0);
    --border: oklch(0.29 0 0);
    --accent: oklch(0.97 0 0);
  }
}
:focus-visible { outline: 2px solid var(--foreground); outline-offset: 2px; }
</style>
"""


def _safe_strip_box(match: re.Match[str]) -> str:
    whole = match.group(0)
    open_end = whole.find(">")
    close_start = whole.rfind("</")
    open_tag = whole[: open_end + 1] if open_end >= 0 else whole
    inner = whole[open_end + 1 : close_start] if open_end >= 0 and close_start > open_end else ""
    if _TEMPLATE_EXPR.search(whole) or re.search(r"<[a-z]", inner, re.I):
        return whole
    if re.search(r"\b(?:id|data-[a-z0-9_-]+|aria-live|role)\s*=", open_tag, re.I):
        return whole
    return ""


def _has_custom_design_system(css: str) -> bool:
    """Return True when the document already defines its own CSS custom-property token system."""
    return len(set(_CUSTOM_PROP_DEF.findall(css))) >= 3


def apply_design(text: str, suffix: str) -> str:
    """Apply the design-rules list to one HTML or CSS document."""
    if suffix in {".css", ".scss"}:
        custom_system = _has_custom_design_system(text)
        rewritten = _rewrite_stylesheet(text, preserve_design=custom_system)
        return _ensure_tokens(rewritten)
    if suffix not in {".html", ".htm"}:
        return text
    all_css = "\n".join(match.group(2) for match in _STYLE_TAG.finditer(text))
    custom_system = _has_custom_design_system(all_css)
    text = _STYLE_TAG.sub(
        lambda match: match.group(0)
        if _TEMPLATE_EXPR.search(match.group(2))
        else match.group(1) + _rewrite_stylesheet(match.group(2), preserve_design=custom_system) + match.group(3),
        text,
    )
    text = _STYLE_ATTR.sub(
        lambda match: match.group(0)
        if _TEMPLATE_EXPR.search(match.group(3))
        else match.group(1)
        + match.group(2)
        + _rewrite_declarations("body", match.group(3), preserve_design=custom_system)
        + match.group(2),
        text,
    )
    text = _rewrite_classes(text)
    text = _EYEBROW.sub(_safe_strip_box, text)
    text = _PILL.sub(_safe_strip_box, text)
    text = _unnest_cards(text)
    if not custom_system:
        text = _TEXT.sub(_sentence_node, text)
        text = _flatten_icons(text)
    return _ensure_checks(text)


def _rewrite_stylesheet(css: str, *, preserve_design: bool = False) -> str:
    pieces: list[str] = []
    cursor = 0
    while cursor < len(css):
        brace = css.find("{", cursor)
        if brace < 0:
            pieces.append(css[cursor:])
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
            pieces.append(css[cursor:])
            break
        selector = css[cursor:brace]
        body = css[brace + 1 : end - 1]
        if "{" in body:
            body = _rewrite_stylesheet(body, preserve_design=preserve_design)
        else:
            body = _rewrite_declarations(selector, body, preserve_design=preserve_design)
        if body.strip():
            pieces.append(selector + "{" + body + "}")
        cursor = end
    return "".join(pieces)


_THEME_SELECTOR = re.compile(r"(?::root\b|\[data-theme\b|\.(?:dark|light)\b)", re.I)
_CUSTOM_PROP_DEF = re.compile(r"(--[A-Za-z0-9_-]+)\s*:")


def _is_theme_selector(selector: str) -> bool:
    return _THEME_SELECTOR.search(selector) is not None


def _rewrite_declarations(selector: str, body: str, *, preserve_design: bool = False) -> str:
    floats = _FLOAT.search(selector) is not None or _POSITION.search(body) is not None
    keep_hex = _is_theme_selector(selector) or preserve_design
    written: list[str] = []
    changed = False
    for decl in body.split(";"):
        if ":" not in decl:
            if decl.strip():
                written.append(decl)
            continue
        prop, _, value = decl.partition(":")
        name = prop.strip().lower()
        updated = value
        if name in _MOTION_PROPS:
            updated = _motion(updated)
        if name == "font-weight" and not preserve_design:
            updated = _weight(updated)
        if name == "text-transform" and "uppercase" in updated.lower() and not preserve_design:
            changed = True
            continue
        if name == "text-shadow" or (name == "filter" and "drop-shadow" in updated.lower()):
            changed = True
            continue
        if name == "box-shadow" and not floats and not preserve_design:
            changed = True
            continue
        if any(kind in updated.lower() for kind in _GRADIENT):
            changed = True
            continue
        if not keep_hex and not name.startswith("--"):
            updated = _HEX.sub(lambda match, prop_name=name: _token(prop_name, match.group(0)), updated)
        if updated != value:
            changed = True
        written.append(prop + ":" + updated)
    if not changed:
        return body
    rebuilt = ";".join(written)
    if body.strip().endswith(";") and rebuilt and not rebuilt.endswith(";"):
        rebuilt += ";"
    return rebuilt


def _motion(value: str) -> str:
    def milliseconds(match: re.Match[str]) -> str:
        return "200ms" if int(match.group(1)) > 300 else match.group(0)

    def seconds(match: re.Match[str]) -> str:
        return "0.2s" if float(match.group(1)) > 0.3 else match.group(0)

    def bezier(match: re.Match[str]) -> str:
        numbers = [float(item) for item in re.findall(r"-?\d*\.?\d+", match.group(0))]
        if any(number < 0 or number > 1 for number in numbers):
            return "ease-out"
        return match.group(0)

    value = re.sub(r"(\d+)ms\b", milliseconds, value)
    value = re.sub(r"(\d*\.\d+|\d+)s\b", seconds, value)
    value = re.sub(r"cubic-bezier\([^)]*\)", bezier, value)
    value = re.sub(r"\bbounce\b", "ease-out", value)
    return value.replace("ease-in-out", "ease-out")


def _weight(value: str) -> str:
    if re.search(r"\b(?:bold|bolder|[6-9]00)\b", value, re.I):
        return " 500"
    return value


def _token(prop: str, color: str) -> str:
    if _purple(color):
        return "var(--accent)"
    if prop.startswith("background"):
        return "var(--background)"
    if "border" in prop:
        return "var(--border)"
    if prop in {"color", "fill", "stroke", "outline-color"}:
        return "var(--foreground)"
    return "var(--text-secondary)"


def _purple(color: str) -> bool:
    raw = color[1:]
    if len(raw) == 3:
        raw = "".join(char * 2 for char in raw)
    if len(raw) != 6:
        return False
    try:
        red, green, blue = int(raw[0:2], 16), int(raw[2:4], 16), int(raw[4:6], 16)
    except ValueError:
        return False
    return red > 70 and blue > 140 and green < 90 and blue > red


def _ensure_tokens(css: str) -> str:
    if ":root" in css or "var(--" not in css:
        return css
    return _ROOT + css


def _rewrite_classes(html: str) -> str:
    def replace(match: re.Match[str]) -> str:
        classes = match.group(3).split()
        floats = any(name in {"fixed", "absolute", "sticky"} or "modal" in name or "dialog" in name for name in classes)
        gradient = any(name.startswith("bg-gradient") for name in classes)
        kept: list[str] = []
        for name in classes:
            if name in {"font-bold", "font-semibold", "font-extrabold", "font-black"}:
                kept.append("font-medium")
            elif name in {"uppercase", "animate-bounce"}:
                continue
            elif gradient and (name.startswith("bg-gradient") or name.startswith(("from-", "to-", "via-"))):
                continue
            elif name in {"shadow-md", "shadow-lg", "shadow-xl", "shadow-2xl"} and not floats:
                continue
            elif name in {"duration-500", "duration-700", "duration-1000"}:
                kept.append("duration-200")
            else:
                kept.append(name)
        return match.group(1) + match.group(2) + " ".join(kept) + match.group(2)

    return _CLASS.sub(replace, html)


def _sentence_node(match: re.Match[str]) -> str:
    if _TEMPLATE_EXPR.search(match.group(2)):
        return match.group(0)
    return match.group(1) + _sentence(match.group(2)) + match.group(3)


def _sentence(text: str) -> str:
    letters = [char for char in text if char.isalpha()]
    if len(letters) < 4:
        return text
    if all(char.isupper() for char in letters):
        lowered = text.lower()
        for index, char in enumerate(lowered):
            if char.isalpha():
                return lowered[:index] + char.upper() + lowered[index + 1 :]
        return lowered
    words = text.split(" ")
    bare = [word for word in words if re.sub(r"[^A-Za-z]", "", word)]
    if len(bare) < 2 or not all(_title_word(word) for word in bare):
        return text
    rebuilt: list[str] = []
    first = True
    for word in words:
        core = re.sub(r"[^A-Za-z]", "", word)
        if not core:
            rebuilt.append(word)
            continue
        if core.isupper() and len(core) <= 4:
            rebuilt.append(word)
        elif first:
            rebuilt.append(word)
            first = False
        else:
            rebuilt.append(word.lower())
            first = False
    return " ".join(rebuilt)


def _title_word(word: str) -> bool:
    core = re.sub(r"[^A-Za-z]", "", word)
    return bool(core) and (core.isupper() and len(core) <= 4 or core[:1].isupper())


def _unnest_cards(html: str) -> str:
    pieces: list[str] = []
    cursor = 0
    stack: list[bool] = []
    for match in _TAG.finditer(html):
        pieces.append(html[cursor : match.start()])
        cursor = match.end()
        if match.group(1):
            if stack:
                stack.pop()
            pieces.append(match.group(0))
            continue
        attrs = match.group(3)
        closing = attrs.rstrip().endswith("/")
        card = _class_has(attrs, "card")
        if card and any(stack):
            attrs = _remove_class(attrs, "card")
            card = False
        if not closing:
            stack.append(card)
        pieces.append(f"<{match.group(2)}{attrs}>")
    pieces.append(html[cursor:])
    return "".join(pieces)


def _flatten_icons(html: str) -> str:
    def replace(match: re.Match[str]) -> str:
        attrs = match.group(2)
        inner = match.group(3).strip()
        names = _class_names(attrs)
        if "icon" not in names and len(inner) != 1:
            return match.group(0)
        attrs = re.sub(r"border-radius\s*:\s*(?:50%|9999px|999px)\s*;?", "", attrs, flags=re.I)
        attrs = _remove_class(attrs, "rounded-full")
        return f"<{match.group(1)}{attrs}>{match.group(3)}</{match.group(1)}>"

    return _ICON.sub(replace, html)


def _class_has(attrs: str, name: str) -> bool:
    return name in _class_names(attrs)


def _class_names(attrs: str) -> list[str]:
    match = _CLASS_VALUE.search(attrs)
    if match is None:
        return []
    return match.group(2).split()


def _remove_class(attrs: str, name: str) -> str:
    match = _CLASS_VALUE.search(attrs)
    if match is None:
        return attrs
    kept = [item for item in match.group(2).split() if item != name]
    return attrs[: match.start(2)] + " ".join(kept) + attrs[match.end(2) :]


_LIGHT_TOKENS = (
    ("--background", "oklch(0.97 0.003 106)"),
    ("--surface", "oklch(1 0 0)"),
    ("--foreground", "oklch(0.23 0 0)"),
    ("--text-secondary", "oklch(0.48 0 0)"),
    ("--border", "oklch(0.91 0.005 106)"),
    ("--accent", "oklch(0.23 0 0)"),
)
_DARK_TOKENS = (
    ("--background", "oklch(0.19 0 0)"),
    ("--surface", "oklch(0.23 0 0)"),
    ("--foreground", "oklch(0.97 0 0)"),
    ("--text-secondary", "oklch(0.80 0 0)"),
    ("--border", "oklch(0.29 0 0)"),
    ("--accent", "oklch(0.97 0 0)"),
)


def _ensure_checks(html: str) -> str:
    if 'data-vibecleaner="design"' in html or "</head>" not in html.lower():
        return html
    existing_css = "\n".join(match.group(2) for match in _STYLE_TAG.finditer(html))
    defined_props = set(_CUSTOM_PROP_DEF.findall(existing_css))
    has_own_theme = bool(defined_props)
    referenced_vc_tokens = {
        name for name, _ in _LIGHT_TOKENS if f"var({name})" in existing_css and name not in defined_props
    }
    light_to_add = [
        (name, val)
        for name, val in _LIGHT_TOKENS
        if name not in defined_props and (not has_own_theme or name in referenced_vc_tokens)
    ]
    dark_to_add = [
        (name, val)
        for name, val in _DARK_TOKENS
        if name not in defined_props and (not has_own_theme or name in referenced_vc_tokens)
    ]
    blocks: list[str] = []
    if light_to_add:
        body = "\n".join(f"  {name}: {val};" for name, val in light_to_add)
        blocks.append(f":root {{\n{body}\n}}")
    if "max-width: 390px" not in existing_css and not has_own_theme:
        blocks.append("@media (max-width: 390px) {\n  img, svg, video { max-width: 100%; height: auto; }\n}")
    if dark_to_add and "prefers-color-scheme: dark" not in existing_css:
        body = "\n".join(f"    {name}: {val};" for name, val in dark_to_add)
        blocks.append(f"@media (prefers-color-scheme: dark) {{\n  :root {{\n{body}\n  }}\n}}")
    if ":focus-visible" not in existing_css:
        outline_token = "var(--foreground)" if ("--foreground" in defined_props or any(n == "--foreground" for n, _ in light_to_add)) else "currentColor"
        blocks.append(f":focus-visible {{ outline: 2px solid {outline_token}; outline-offset: 2px; }}")
    if not blocks:
        return html
    injected = '<style data-vibecleaner="design">\n' + "\n".join(blocks) + "\n</style>\n"
    return re.sub(r"</head>", injected + "</head>", html, count=1, flags=re.I)
