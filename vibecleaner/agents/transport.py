"""HTTP for local and cloud model calls. Loopback checks happen before any socket."""

from __future__ import annotations

import json
import os
import ssl
import urllib.error
import urllib.request
from collections.abc import Mapping

from vibecleaner.fix_contract import ProviderError

_LOOPBACK = frozenset({"127.0.0.1", "localhost", "::1"})


class Unreachable(Exception):
    """The TCP connection failed or timed out."""


def require_loopback(url: str) -> str:
    """Return ``url`` without a trailing slash. Reject anything that is not loopback."""
    raw = url.strip()
    parsed = urllib.parse.urlsplit(raw)
    host = parsed.hostname
    if parsed.scheme not in {"http", "https"} or not host:
        raise ProviderError(f"local model URL must be an http(s) loopback address, got {url}")
    if parsed.username or parsed.password:
        raise ProviderError("local model URL must not include credentials")
    if host not in _LOOPBACK:
        raise ProviderError(f"local model URL must stay on loopback, got {url}")
    path = parsed.path.rstrip("/")
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


def openai_url(base: str, suffix: str) -> str:
    """Join an OpenAI-compatible base with ``models`` or ``chat/completions``."""
    root = base.rstrip("/")
    if root.endswith("/v1"):
        return f"{root}/{suffix}"
    return f"{root}/v1/{suffix}"


def ollama_show_url(base: str) -> str:
    root = base.rstrip("/")
    if root.endswith("/v1"):
        root = root[: -len("/v1")]
    return f"{root}/api/show"


def body_text(body: bytes, limit: int = 300) -> str:
    text = body.decode("utf-8", errors="replace").strip()
    if len(text) <= limit:
        return text
    return text[:limit] + "…"


def fetch(
    method: str,
    url: str,
    *,
    payload: Mapping[str, object] | None = None,
    headers: Mapping[str, str] | None = None,
    timeout_s: float,
    local: bool,
) -> tuple[int, bytes]:
    """Perform one HTTP call. Transport failures raise ``Unreachable`` or ``ProviderError``."""
    if local:
        require_loopback(url)
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    request_headers = {"Accept": "application/json"}
    if data is not None:
        request_headers["Content-Type"] = "application/json"
    if headers:
        request_headers.update(headers)
    request = urllib.request.Request(url, data=data, headers=request_headers, method=method)
    handlers: list[urllib.request.BaseHandler] = [
        _LoopbackRedirect() if local else urllib.request.HTTPRedirectHandler(),
        _https_handler(),
    ]
    opener = urllib.request.build_opener(*handlers)
    try:
        with opener.open(request, timeout=timeout_s) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()
    except TimeoutError as exc:
        raise Unreachable(f"{method} {url} timed out") from exc
    except urllib.error.URLError as exc:
        raise Unreachable(f"{method} {url} failed: {exc.reason}") from exc
    except OSError as exc:
        raise Unreachable(f"{method} {url} failed: {exc}") from exc


def decode_json(body: bytes, *, what: str) -> object:
    try:
        return json.loads(body.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ProviderError(f"{what} returned non-JSON: {exc}") from exc


def _ssl_context() -> ssl.SSLContext:
    """Return an SSLContext that uses certifi on macOS/bundled Pythons when no env CA is set."""
    if os.environ.get("SSL_CERT_FILE") or os.environ.get("SSL_CERT_DIR"):
        return ssl.create_default_context()
    try:
        import certifi
    except ImportError:
        return ssl.create_default_context()
    return ssl.create_default_context(cafile=certifi.where())


def _https_handler() -> urllib.request.HTTPSHandler:
    return urllib.request.HTTPSHandler(context=_ssl_context())


class _LoopbackRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlsplit(newurl)
        if parsed.hostname not in _LOOPBACK:
            raise ProviderError(f"local model server redirected off loopback to {newurl}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)
