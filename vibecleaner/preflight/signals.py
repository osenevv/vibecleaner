"""Coarse product signals, the inferred summary, and the detected stack."""

from __future__ import annotations

import json
from pathlib import PurePosixPath

from vibecleaner.preflight.patterns import (
    _ACCOUNTS,
    _AUTH_PRESENT,
    _DB,
    _EMAIL_SDK,
    _FASTAPI_TITLE,
    _HOST_URL,
    _HOSTS,
    _HTTP,
    _PAYMENT,
    _ROUTE_PATH,
    _STACK_SIGNALS,
)
from vibecleaner.preflight.results import CheckResult, Status, _NO_PAY, _NO_PAY_EVIDENCE, _make
from vibecleaner.preflight.view import RepoView, _is_scannable_source, _is_test_path

__all__ = [
    "_database",
    "_has_pages",
    "_na_payment",
    "_personal_data",
    "_service",
    "_vendors",
]


def _has_ui(view: RepoView) -> bool:
    for source in view.files:
        if _is_test_path(source.path):
            continue
        path = source.path
        suffix = PurePosixPath(path).suffix.lower()
        name = PurePosixPath(path).name
        if name.startswith("page.") or name in {"index.html", "index.htm"}:
            return True
        if suffix in {".html", ".htm", ".vue"}:
            return True
        if suffix in {".tsx", ".jsx"} and "/api/" not in f"/{path}":
            return True
    return False


def _has_pages(view: RepoView) -> bool:
    for source in view.files:
        name = PurePosixPath(source.path).name
        if name.startswith("page.") or name in {"index.html", "index.htm"}:
            return True
    return False


def _payments(view: RepoView) -> bool:
    return bool(view.search_usage(_PAYMENT, skip_tests=True, limit=1))


def _auth(view: RepoView) -> bool:
    return bool(view.search_usage(_AUTH_PRESENT, skip_tests=True, limit=1))


def _accounts(view: RepoView) -> bool:
    return bool(view.search_usage(_ACCOUNTS, skip_tests=True, limit=1))


def _database(view: RepoView) -> bool:
    return _DB.search(view.usage_blob(skip_tests=True)) is not None


def _http(view: RepoView) -> bool:
    return _HTTP.search(view.usage_blob(skip_tests=True)) is not None


def _personal_data(view: RepoView) -> bool:
    return _accounts(view) or _payments(view) or _auth(view)


def _service(view: RepoView) -> bool:
    return _http(view) or _has_ui(view) or _payments(view)


def _na_payment(check_id: int, consequence: str) -> CheckResult:
    return _make(check_id, Status.NOT_APPLICABLE, _NO_PAY, _NO_PAY_EVIDENCE, consequence)


def _readme_paragraph(view: RepoView) -> str:
    for source in view.files:
        if PurePosixPath(source.path).name.lower() not in {"readme.md", "readme.rst", "readme.txt", "readme"}:
            continue
        paragraph: list[str] = []
        for line in source.text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith(("#", "![", "[!")):
                if paragraph:
                    break
                continue
            paragraph.append(stripped)
        text = " ".join(paragraph).strip()
        if text:
            return text[:400]
    return ""


def _package_meta(view: RepoView) -> tuple[str, str]:
    for source in view.files:
        if PurePosixPath(source.path).name != "package.json":
            continue
        if source.path.count("/") > 1:
            continue
        try:
            data = json.loads(source.text)
        except json.JSONDecodeError:
            continue
        if not isinstance(data, dict):
            continue
        name = data.get("name") if isinstance(data.get("name"), str) else ""
        description = data.get("description") if isinstance(data.get("description"), str) else ""
        return name.strip(), description.strip()
    return "", ""


def _route_hints(view: RepoView) -> list[str]:
    hints: list[str] = []
    for source in view.files:
        if _is_test_path(source.path) or not _is_scannable_source(source):
            continue
        for match in _ROUTE_PATH.finditer(view.comments_only_blanked(source)):
            path = match.group(1) or match.group(2)
            if path and path not in hints:
                hints.append(path)
            if len(hints) >= 6:
                return hints
    return hints


def _page_hints(view: RepoView) -> list[str]:
    pages: list[str] = []
    for source in view.files:
        if _is_test_path(source.path) or not _is_scannable_source(source):
            continue
        pure = PurePosixPath(source.path)
        if not pure.name.startswith("page."):
            continue
        parts = [part for part in pure.parts[:-1] if part not in {"app", "src", "pages"} and not part.startswith("(")]
        route = "/" + "/".join(parts) if parts else "/"
        if route not in pages:
            pages.append(route)
    return pages[:6]


def infer_summary(view: RepoView) -> str:
    """One paragraph. It is inferred from names and routes, not confirmed by the owner."""
    bits: list[str] = []
    readme = _readme_paragraph(view)
    name, description = _package_meta(view)
    routes = _route_hints(view)
    pages = _page_hints(view)
    titles = []
    for source in view.files:
        if _is_test_path(source.path) or not _is_scannable_source(source):
            continue
        match = _FASTAPI_TITLE.search(view.comments_only_blanked(source))
        if match:
            titles.append(match.group(1))
    if readme:
        sentence = readme if readme.endswith(".") else readme + "."
        bits.append(sentence)
    elif name and description:
        bits.append(f"The package is {name}: {description}.")
    elif description:
        bits.append(description if description.endswith(".") else description + ".")
    elif name:
        bits.append(f"The package name is {name}.")
    if titles:
        bits.append(f"A server title in code is {titles[0]}.")
    if pages:
        bits.append("Pages include " + ", ".join(pages) + ".")
    if routes:
        bits.append("Routes include " + ", ".join(routes) + ".")
    if _payments(view) and _auth(view):
        bits.append("A signed-in person appears to start a paid action and receive an order or receipt.")
    elif _auth(view):
        bits.append("A signed-in person calls those entry points and receives the handler's result.")
    elif routes or pages:
        bits.append("A person uses those entry points and receives the handler's result.")
    else:
        bits.append("The scanned files do not name a home page or an HTTP route, so the result a person gets is not visible.")
    lead = "Inferred from routes, page names, the README, and package.json, not confirmed with the owner: "
    body = " ".join(bits)
    if body:
        body = body[0].lower() + body[1:]
    return lead + body


def detect_stack(view: RepoView) -> list[str]:
    hay = view.usage_blob() + "\n" + "\n".join(source.path for source in view.files)
    return [label for label, pattern in _STACK_SIGNALS if pattern.search(hay)]


def _vendors(view: RepoView) -> list[str]:
    stack = detect_stack(view)
    extra: list[str] = []
    urls = _HOST_URL.findall(view.blob())
    for pattern, label in _HOSTS:
        if any(pattern.search(url) for url in urls) and label not in extra:
            extra.append(label)
    if _EMAIL_SDK.search(view.usage_blob()):
        extra.append("email provider")
    ordered: list[str] = []
    for item in stack + extra:
        if item not in ordered:
            ordered.append(item)
    return ordered
