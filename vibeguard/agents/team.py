"""Choose who writes patches and who judges them."""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path

from vibeguard.agents.hosts import host_from_name
from vibeguard.agents.local import detect_local_servers, read_local_config
from vibeguard.agents.providers import cloud_providers, local_providers
from vibeguard.fix_contract import Provider, ProviderError, Team

_HOST_LABELS = {
    "claude-code": "Claude Code",
    "codex": "Codex",
    "antigravity": "Antigravity",
}
_FAMILY_LABELS = {
    "gemini": "Gemini",
    "anthropic": "Anthropic",
    "openai": "OpenAI",
}
_NO_LOCAL = (
    "no local model server found on 127.0.0.1 "
    "(ports 11434 Ollama, 1234 LM Studio, 8080 llama.cpp, 8000 vLLM). "
    "Start one, or set VIBEGUARD_LOCAL_URL."
)


def select_team(
    root: Path,
    *,
    local: bool | None = None,
    env: Mapping[str, str] | None = None,
) -> Team:
    """Pick a host and providers.

    ``local=None`` uses loopback servers when they answer. ``local=True`` uses only those
    servers and raises ``ProviderError`` when none answer. ``local=False`` skips detection.
    The host is ``VIBEGUARD_HOST`` when it is ``claude-code``, ``codex``, or ``antigravity``.
    """
    environ = dict(os.environ if env is None else env)
    host_name = environ.get("VIBEGUARD_HOST", "").strip()
    host = host_from_name(host_name) if host_name else None
    if local is False:
        return Team(host=host, providers=cloud_providers(environ))
    _apply_local_config(root, environ)
    servers = detect_local_servers(environ)
    local_models = local_providers(servers)
    if local is True and not local_models:
        raise ProviderError(_NO_LOCAL)
    clouds = () if local is True else cloud_providers(environ)
    return Team(host=host, providers=local_models + clouds)


def describe_team(team: Team) -> str:
    """One plain line naming who edits and how many other models judge."""
    count = len(team.providers)
    if team.host is not None:
        label = _HOST_LABELS.get(team.host.name, team.host.name)
        if count == 0:
            return f"{label} agents"
        noun = "model" if count == 1 else "models"
        return f"{label} agents, judged by {count} other {noun}"
    if count == 0:
        return "No agent or model available"
    if count == 1:
        return _provider_label(team.providers[0])
    if all(provider.local for provider in team.providers):
        return "Local models"
    return f"{count} models"


def _apply_local_config(root: Path, environ: dict[str, str]) -> None:
    configured = read_local_config(root)
    if configured is None:
        return
    url, model = configured
    if url and not environ.get("VIBEGUARD_LOCAL_URL", "").strip():
        environ["VIBEGUARD_LOCAL_URL"] = url
    if model and not environ.get("VIBEGUARD_LOCAL_MODEL", "").strip():
        environ["VIBEGUARD_LOCAL_MODEL"] = model


def _provider_label(provider: Provider) -> str:
    if provider.local:
        return "A local model"
    return _FAMILY_LABELS.get(provider.family, "A model")
