"""Find OpenAI-compatible model servers on loopback."""

from __future__ import annotations

import json
import logging
import os
import threading
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from vibeguard.agents.transport import (
    Unreachable,
    body_text,
    decode_json,
    fetch,
    ollama_show_url,
    openai_url,
    require_loopback,
)
from vibeguard.fix_contract import Capabilities, ProviderError

log = logging.getLogger(__name__)

_DEFAULT_TARGETS: tuple[tuple[int, str], ...] = (
    (11434, "ollama"),
    (1234, "lmstudio"),
    (8080, "llama.cpp"),
    (8000, "vllm"),
)
_KIND_BY_PORT = dict(_DEFAULT_TARGETS)
_DEFAULT_CONTEXT = 8_000
_DEFAULT_CAPS = Capabilities(_DEFAULT_CONTEXT)
_CONTEXT_KEYS = frozenset(
    {
        "context_length",
        "context_window",
        "max_model_len",
        "max_context_length",
        "n_ctx",
        "n_ctx_train",
    }
)
_TOOL_LABELS = frozenset({"tools", "tool", "tool_calls", "function_calling", "function-calling"})
_VISION_LABELS = frozenset({"vision", "image", "images", "multimodal"})
_CHAT_LABELS = frozenset({"completion", "chat", "tools", "vision"})
_EMBED_LABELS = frozenset({"embedding", "embeddings", "embed"})


@dataclass(frozen=True)
class LocalServer:
    url: str
    kind: str
    models: tuple[str, ...]
    capabilities: tuple[Capabilities, ...] = ()


def detect_local_servers(
    env: Mapping[str, str] | None = None,
    *,
    timeout_s: float = 0.3,
) -> list[LocalServer]:
    """Return loopback servers. ``VIBEGUARD_LOCAL_URL`` and ``VIBEGUARD_LOCAL_MODEL`` win over port probes."""
    environ = os.environ if env is None else env
    url = _value(environ, "VIBEGUARD_LOCAL_URL")
    model = _value(environ, "VIBEGUARD_LOCAL_MODEL")
    if url:
        base = require_loopback(url)
        server = _load_server(base, _kind_for(base), model, timeout_s, required=True)
        return [] if server is None else [server]
    found = _probe_targets(_DEFAULT_TARGETS, timeout_s)
    if not model:
        return found
    return [server for server in (_keep_model(item, model) for item in found) if server is not None]


def read_local_config(root: Path) -> tuple[str, str] | None:
    """Return ``(url, model)`` from ``.vibeguard/config.json``, or None when the key is absent."""
    path = root / ".vibeguard" / "config.json"
    if not path.is_file():
        return None
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ProviderError(f"cannot read {path}: {exc}") from exc
    try:
        data = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError as exc:
        raise ProviderError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict) or "local" not in data:
        return None
    local = data["local"]
    if not isinstance(local, dict):
        raise ProviderError(f'{path} key "local" must be an object')
    url = local.get("url", "")
    model = local.get("model", "")
    if url is None:
        url = ""
    if model is None:
        model = ""
    if not isinstance(url, str) or not isinstance(model, str):
        raise ProviderError(f'{path} local url and model must be strings')
    url = url.strip()
    model = model.strip()
    if not url and not model:
        return None
    return url, model


def _probe_targets(targets: Sequence[tuple[int, str]], timeout_s: float) -> list[LocalServer]:
    found: list[LocalServer | None] = [None] * len(targets)
    errors: list[BaseException | None] = [None] * len(targets)

    def run(index: int, port: int, kind: str) -> None:
        try:
            found[index] = _load_server(
                f"http://127.0.0.1:{port}",
                kind,
                None,
                timeout_s,
                required=False,
            )
        except Exception as exc:
            errors[index] = exc

    threads = [
        threading.Thread(target=run, args=(index, port, kind), daemon=True)
        for index, (port, kind) in enumerate(targets)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    for exc in errors:
        if exc is not None:
            raise exc
    return [server for server in found if server is not None]


def _load_server(
    url: str,
    kind: str,
    model: str | None,
    timeout_s: float,
    *,
    required: bool,
) -> LocalServer | None:
    try:
        status, body = fetch("GET", openai_url(url, "models"), timeout_s=timeout_s, local=True)
    except Unreachable as exc:
        if required:
            raise ProviderError(f"local model server at {url} did not respond: {exc}") from exc
        return None
    if status != 200:
        if required:
            raise ProviderError(f"local model server at {url} returned HTTP {status}: {body_text(body)}")
        return None
    try:
        payload = decode_json(body, what=f"local model server at {url}")
    except ProviderError:
        if required:
            raise
        return None
    listed = _models_from_payload(payload)
    if listed is None:
        if required:
            raise ProviderError(f"local model server at {url} did not return a model list")
        return None
    chat = [(name, caps) for name, caps in listed if not _name_is_embedding(name)]
    chat = _with_show(url, chat, timeout_s)
    if model:
        chat = [(name, caps) for name, caps in chat if name == model]
        if not chat:
            if required:
                raise ProviderError(f"local server at {url} is not serving {model}")
            return None
    if not chat:
        if required:
            raise ProviderError(f"local server at {url} has no chat model")
        return None
    names, caps = zip(*chat)
    return LocalServer(url=url, kind=kind, models=tuple(names), capabilities=tuple(caps))


def _with_show(
    url: str,
    chat: list[tuple[str, Capabilities]],
    timeout_s: float,
) -> list[tuple[str, Capabilities]]:
    enriched: list[tuple[str, Capabilities]] = []
    show_missing = False
    for name, caps in chat:
        if show_missing:
            enriched.append((name, caps))
            continue
        shown = _show_model(url, name, timeout_s)
        if shown is None:
            show_missing = True
            enriched.append((name, caps))
            continue
        if shown is False:
            continue
        enriched.append((name, shown))
    return enriched


def _show_model(url: str, name: str, timeout_s: float) -> Capabilities | None | bool:
    """Return capabilities, False to drop an embedding model, or None when show is absent."""
    try:
        status, body = fetch(
            "POST",
            ollama_show_url(url),
            payload={"model": name},
            timeout_s=timeout_s,
            local=True,
        )
    except Unreachable as exc:
        log.warning("local model metadata unavailable at %s: %s", url, exc)
        return None
    if status == 404:
        return None
    if status != 200:
        log.warning("local model metadata at %s returned HTTP %s", url, status)
        return None
    try:
        payload = decode_json(body, what=f"model metadata at {url}")
    except ProviderError as exc:
        log.warning("%s", exc)
        return None
    if not isinstance(payload, dict):
        return None
    labels = payload.get("capabilities")
    if isinstance(labels, list) and _labels_are_embedding(labels):
        return False
    parsed = _caps_from_show(payload)
    return parsed if parsed is not None else None


def _models_from_payload(payload: object) -> list[tuple[str, Capabilities]] | None:
    if not isinstance(payload, dict):
        return None
    data = payload.get("data")
    if not isinstance(data, list):
        return None
    found: list[tuple[str, Capabilities]] = []
    for item in data:
        parsed = _one_model(item)
        if parsed is not None:
            found.append(parsed)
    return found


def _one_model(item: object) -> tuple[str, Capabilities] | None:
    if isinstance(item, str):
        name = item.strip()
        return (name, _DEFAULT_CAPS) if name else None
    if not isinstance(item, dict):
        return None
    raw = item.get("id", item.get("name"))
    if not isinstance(raw, str) or not raw.strip():
        return None
    return raw.strip(), _caps_from_model(item)


def _caps_from_model(item: dict) -> Capabilities:
    meta = item.get("meta") if isinstance(item.get("meta"), dict) else {}
    context = _context_in(item) or _context_in(meta)
    tools = _flag(item, "tool_calls", "supports_tools") or _flag(meta, "tool_calls", "supports_tools")
    vision = _flag(item, "vision", "supports_vision") or _flag(meta, "vision", "supports_vision")
    return Capabilities(context or _DEFAULT_CONTEXT, tool_calls=tools, vision=vision)


def _caps_from_show(payload: dict) -> Capabilities | None:
    info = payload.get("model_info") if isinstance(payload.get("model_info"), dict) else {}
    labels = payload.get("capabilities") if isinstance(payload.get("capabilities"), list) else None
    context = _context_in(info) or _context_in(payload)
    if labels is None and context is None:
        return None
    tools, vision = _label_flags(labels or [])
    return Capabilities(context or _DEFAULT_CONTEXT, tool_calls=tools, vision=vision)


def _context_in(mapping: dict) -> int | None:
    for key, value in mapping.items():
        leaf = str(key).lower().rsplit(".", 1)[-1]
        if leaf not in _CONTEXT_KEYS and str(key).lower() not in _CONTEXT_KEYS:
            continue
        parsed = _positive_int(value)
        if parsed is not None:
            return parsed
    return None


def _positive_int(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int) and value > 0:
        return value
    if isinstance(value, float) and value > 0 and value.is_integer():
        return int(value)
    return None


def _flag(mapping: dict, *keys: str) -> bool:
    return any(mapping.get(key) is True for key in keys)


def _label_flags(labels: list) -> tuple[bool, bool]:
    names = {str(item).lower() for item in labels}
    return bool(names & _TOOL_LABELS), bool(names & _VISION_LABELS)


def _labels_are_embedding(labels: list) -> bool:
    names = {str(item).lower() for item in labels}
    return bool(names & _EMBED_LABELS) and not bool(names & _CHAT_LABELS)


def _name_is_embedding(name: str) -> bool:
    return "embed" in name.lower()


def _keep_model(server: LocalServer, model: str) -> LocalServer | None:
    pairs = [
        (name, caps)
        for name, caps in zip(server.models, _aligned(server))
        if name == model
    ]
    if not pairs:
        return None
    names, caps = zip(*pairs)
    return LocalServer(url=server.url, kind=server.kind, models=tuple(names), capabilities=tuple(caps))


def _aligned(server: LocalServer) -> tuple[Capabilities, ...]:
    if len(server.capabilities) == len(server.models):
        return server.capabilities
    return tuple(_DEFAULT_CAPS for _ in server.models)


def _kind_for(url: str) -> str:
    return _KIND_BY_PORT.get(urlsplit(url).port or 0, "local")


def _value(env: Mapping[str, str], name: str) -> str | None:
    value = env.get(name, "").strip()
    return value or None
