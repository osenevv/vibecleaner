"""Gemini, Anthropic, and OpenAI-compatible chat providers."""

from __future__ import annotations

import math
import re
from collections.abc import Mapping, Sequence

from vibeguard.agents.local import LocalServer
from vibeguard.agents.transport import Unreachable, body_text, decode_json, fetch, openai_url
from vibeguard.fix_contract import Capabilities, ProviderError

_GEMINI_MODEL = "gemini-2.5-flash"
_ANTHROPIC_MODEL = "claude-sonnet-4-6"
_OPENAI_MODEL = "gpt-4o"
_FAMILY = re.compile(r"[A-Za-z]+")
_CLOUD_TIMEOUT_S = 120.0


class OpenAICompatibleProvider:
    """Chat client for OpenAI and for local servers that speak the same API."""

    def __init__(
        self,
        *,
        name: str,
        family: str,
        local: bool,
        capabilities: Capabilities,
        base_url: str,
        model: str,
        api_key: str | None,
        timeout_s: float = _CLOUD_TIMEOUT_S,
    ) -> None:
        self.name = name
        self.family = family
        self.local = local
        self.capabilities = capabilities
        self.base_url = base_url
        self.model = model
        self._api_key = api_key
        self._timeout_s = timeout_s

    def complete(self, system: str, prompt: str, *, json_mode: bool = False) -> str:
        payload: dict[str, object] = {"model": self.model, "messages": _messages(system, prompt)}
        if json_mode:
            payload["response_format"] = {"type": "json_object"}
        return _choice_text(self._post(payload), self.name)

    def yes_probability(self, system: str, prompt: str) -> float | None:
        constrained = prompt.rstrip() + "\n\nAnswer with one token: yes or no."
        payload: dict[str, object] = {
            "model": self.model,
            "messages": _messages(system, constrained),
            "max_tokens": 1,
            "temperature": 0,
            "logprobs": True,
            "top_logprobs": 5,
        }
        status, body = self._exchange(payload)
        if status != 200:
            if _logprobs_rejected(status, body):
                return None
            self._raise_status(status, body)
        decoded = decode_json(body, what=self.name)
        if not isinstance(decoded, dict):
            raise ProviderError(f"{self.name} returned a non-object response")
        return yes_probability_from(_openai_pairs(decoded))

    def _post(self, payload: Mapping[str, object]) -> dict:
        status, body = self._exchange(payload)
        if status != 200:
            self._raise_status(status, body)
        decoded = decode_json(body, what=self.name)
        if not isinstance(decoded, dict):
            raise ProviderError(f"{self.name} returned a non-object response")
        return decoded

    def _exchange(self, payload: Mapping[str, object]) -> tuple[int, bytes]:
        headers = {}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        url = openai_url(self.base_url, "chat/completions")
        try:
            return fetch(
                "POST",
                url,
                payload=payload,
                headers=headers,
                timeout_s=self._timeout_s,
                local=self.local,
            )
        except Unreachable as exc:
            raise ProviderError(str(exc)) from exc

    def _raise_status(self, status: int, body: bytes) -> None:
        url = openai_url(self.base_url, "chat/completions")
        raise ProviderError(f"POST {url} returned HTTP {status}: {body_text(body)}")


class AnthropicProvider:
    def __init__(self, api_key: str, model: str, base_url: str, *, timeout_s: float = _CLOUD_TIMEOUT_S) -> None:
        self.name = f"anthropic:{model}"
        self.family = "anthropic"
        self.local = False
        self.capabilities = Capabilities(200_000, tool_calls=True, vision=True, logprobs=False)
        self._api_key = api_key
        self._model = model
        self._base_url = base_url.rstrip("/")
        self._timeout_s = timeout_s

    def complete(self, system: str, prompt: str, *, json_mode: bool = False) -> str:
        system_text = system
        if json_mode:
            extra = "Reply with one JSON value and no markdown."
            system_text = f"{system}\n{extra}".strip() if system else extra
        payload: dict[str, object] = {
            "model": self._model,
            "max_tokens": 4096,
            "messages": [{"role": "user", "content": prompt}],
        }
        if system_text:
            payload["system"] = system_text
        url = _anthropic_messages_url(self._base_url)
        try:
            status, body = fetch(
                "POST",
                url,
                payload=payload,
                headers={"x-api-key": self._api_key, "anthropic-version": "2023-06-01"},
                timeout_s=self._timeout_s,
                local=False,
            )
        except Unreachable as exc:
            raise ProviderError(str(exc)) from exc
        if status != 200:
            raise ProviderError(f"POST {url} returned HTTP {status}: {body_text(body)}")
        decoded = decode_json(body, what=self.name)
        return _anthropic_text(decoded, self.name)

    def yes_probability(self, system: str, prompt: str) -> float | None:
        return None


class GeminiProvider:
    def __init__(self, api_key: str, model: str) -> None:
        self.name = f"gemini:{model}"
        self.family = "gemini"
        self.local = False
        self.capabilities = Capabilities(1_048_576, tool_calls=True, vision=True, logprobs=True)
        self._api_key = api_key
        self._model = model

    def complete(self, system: str, prompt: str, *, json_mode: bool = False) -> str:
        response = self._generate(system, prompt, json_mode=json_mode, yes_no=False)
        if response is None:
            raise ProviderError("gemini returned no text")
        text = getattr(response, "text", None)
        if not isinstance(text, str) or not text.strip():
            raise ProviderError("gemini returned no text")
        return text

    def yes_probability(self, system: str, prompt: str) -> float | None:
        constrained = prompt.rstrip() + "\n\nAnswer with one token: yes or no."
        response = self._generate(system, constrained, json_mode=False, yes_no=True)
        if response is None:
            return None
        return yes_probability_from(_gemini_pairs(response))

    def _generate(self, system: str, prompt: str, *, json_mode: bool, yes_no: bool):
        from google.genai import errors, types

        from vibeguard.settings import genai_client

        config: dict[str, object] = {}
        if system:
            config["system_instruction"] = system
        if json_mode:
            config["response_mime_type"] = "application/json"
        if yes_no:
            config["max_output_tokens"] = 1
            config["temperature"] = 0
            config["response_logprobs"] = True
            config["logprobs"] = 5
        try:
            return genai_client(self._api_key).models.generate_content(
                model=self._model,
                contents=prompt,
                config=types.GenerateContentConfig(**config),
            )
        except errors.ClientError as exc:
            if yes_no and "logprob" in str(exc).lower():
                return None
            raise ProviderError(f"gemini request failed: {exc}") from exc
        except errors.APIError as exc:
            raise ProviderError(f"gemini request failed: {exc}") from exc
        except OSError as exc:
            raise ProviderError(f"gemini request failed: {exc}") from exc


def cloud_providers(env: Mapping[str, str]) -> tuple[OpenAICompatibleProvider | AnthropicProvider | GeminiProvider, ...]:
    found: list[OpenAICompatibleProvider | AnthropicProvider | GeminiProvider] = []
    gemini_key = _first(env, "GEMINI_API_KEY", "GOOGLE_API_KEY")
    if gemini_key:
        found.append(GeminiProvider(gemini_key, _first(env, "GEMINI_MODEL", "VIBEGUARD_FIX_MODEL") or _GEMINI_MODEL))
    anthropic_key = _first(env, "ANTHROPIC_API_KEY")
    if anthropic_key:
        found.append(
            AnthropicProvider(
                anthropic_key,
                _first(env, "ANTHROPIC_MODEL") or _ANTHROPIC_MODEL,
                _first(env, "ANTHROPIC_BASE_URL") or "https://api.anthropic.com",
            )
        )
    openai_key = _first(env, "OPENAI_API_KEY")
    if openai_key:
        model = _first(env, "OPENAI_MODEL") or _OPENAI_MODEL
        found.append(
            OpenAICompatibleProvider(
                name=f"openai:{model}",
                family="openai",
                local=False,
                capabilities=Capabilities(128_000, tool_calls=True, vision=True, logprobs=True),
                base_url=_first(env, "OPENAI_BASE_URL") or "https://api.openai.com/v1",
                model=model,
                api_key=openai_key,
            )
        )
    return tuple(found)


def local_providers(servers: Sequence[LocalServer]) -> tuple[OpenAICompatibleProvider, ...]:
    found: list[OpenAICompatibleProvider] = []
    for server in servers:
        caps = server.capabilities
        if len(caps) != len(server.models):
            caps = tuple(Capabilities(8_000) for _ in server.models)
        for model, cap in zip(server.models, caps):
            found.append(
                OpenAICompatibleProvider(
                    name=f"{server.kind}:{model}",
                    family=_local_family(model),
                    local=True,
                    capabilities=cap,
                    base_url=server.url,
                    model=model,
                    api_key=None,
                )
            )
    return tuple(found)


def yes_probability_from(pairs: Sequence[tuple[str, float]]) -> float | None:
    """P(yes) from token log-probabilities of a constrained yes/no answer."""
    yes_lp: float | None = None
    no_lp: float | None = None
    for token, lp in pairs:
        vote = _vote(token)
        if vote == "yes":
            yes_lp = lp if yes_lp is None else max(yes_lp, lp)
        elif vote == "no":
            no_lp = lp if no_lp is None else max(no_lp, lp)
    if yes_lp is None and no_lp is None:
        return None
    if yes_lp is None:
        return 0.0
    if no_lp is None:
        return 1.0
    shift = max(yes_lp, no_lp)
    yes_p = math.exp(yes_lp - shift)
    no_p = math.exp(no_lp - shift)
    return yes_p / (yes_p + no_p)


def _messages(system: str, prompt: str) -> list[dict[str, str]]:
    messages: list[dict[str, str]] = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})
    return messages


def _choice_text(payload: dict, name: str) -> str:
    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
        raise ProviderError(f"{name} returned no choices")
    message = choices[0].get("message")
    content = message.get("content") if isinstance(message, dict) else choices[0].get("text")
    text = _content_text(content)
    if not text:
        raise ProviderError(f"{name} returned no text")
    return text


def _content_text(content: object) -> str:
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return ""
    parts: list[str] = []
    for item in content:
        if isinstance(item, str):
            parts.append(item)
        elif isinstance(item, dict) and isinstance(item.get("text"), str):
            parts.append(item["text"])
    return "".join(parts)


def _openai_pairs(payload: dict) -> list[tuple[str, float]]:
    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
        return []
    logprobs = choices[0].get("logprobs")
    if not isinstance(logprobs, dict):
        return []
    content = logprobs.get("content")
    if not isinstance(content, list) or not content or not isinstance(content[0], dict):
        return []
    step = content[0]
    pairs = [_token_lp(item) for item in step.get("top_logprobs") or []]
    pairs.append(_token_lp(step))
    return [pair for pair in pairs if pair is not None]


def _token_lp(item: object) -> tuple[str, float] | None:
    if not isinstance(item, dict):
        return None
    token = item.get("token")
    lp = item.get("logprob")
    if isinstance(token, str) and isinstance(lp, (int, float)) and not isinstance(lp, bool):
        return token, float(lp)
    return None


def _gemini_pairs(response: object) -> list[tuple[str, float]]:
    candidates = getattr(response, "candidates", None) or []
    if not candidates:
        return []
    result = getattr(candidates[0], "logprobs_result", None)
    if result is None:
        return []
    pairs: list[tuple[str, float]] = []
    top = getattr(result, "top_candidates", None) or []
    if top:
        for item in getattr(top[0], "candidates", None) or []:
            pair = _gemini_token(item)
            if pair is not None:
                pairs.append(pair)
    chosen = getattr(result, "chosen_candidates", None) or []
    if chosen:
        pair = _gemini_token(chosen[0])
        if pair is not None:
            pairs.append(pair)
    return pairs


def _gemini_token(item: object) -> tuple[str, float] | None:
    token = getattr(item, "token", None)
    lp = getattr(item, "log_probability", None)
    if isinstance(token, str) and isinstance(lp, (int, float)) and not isinstance(lp, bool):
        return token, float(lp)
    return None


def _anthropic_text(payload: object, name: str) -> str:
    if not isinstance(payload, dict):
        raise ProviderError(f"{name} returned a non-object response")
    blocks = payload.get("content")
    if not isinstance(blocks, list):
        raise ProviderError(f"{name} returned no text")
    parts = [
        block["text"]
        for block in blocks
        if isinstance(block, dict) and block.get("type") == "text" and isinstance(block.get("text"), str)
    ]
    text = "".join(parts)
    if not text:
        raise ProviderError(f"{name} returned no text")
    return text


def _anthropic_messages_url(base: str) -> str:
    root = base.rstrip("/")
    if root.endswith("/v1"):
        return f"{root}/messages"
    return f"{root}/v1/messages"


def _logprobs_rejected(status: int, body: bytes) -> bool:
    if status not in {400, 404, 422, 501}:
        return False
    return "logprob" in body.decode("utf-8", errors="replace").lower()


def _vote(token: str) -> str | None:
    text = token.strip().strip(".,;:!?\"'`").lower()
    if text == "yes":
        return "yes"
    if text == "no":
        return "no"
    return None


def _local_family(model: str) -> str:
    match = _FAMILY.match(model)
    return f"local:{match.group(0).lower()}" if match else "local:model"


def _first(env: Mapping[str, str], *names: str) -> str | None:
    for name in names:
        value = env.get(name, "").strip()
        if value:
            return value
    return None
