"""Multi-provider decision API routing for Layer 2 semantic checks."""

from __future__ import annotations

import asyncio
import json
import os
import urllib.error
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass

from vibecleaner.cache import ChunkVerdict
from vibecleaner.models import LAYER2_KEY_SUFFIX, LAYER2_RULE_IDS, RULES, CodeUnit
from vibecleaner.redact import redact_secrets


@dataclass(frozen=True)
class JudgeRoute:
    provider: str
    model: str
    url: str
    api_key: str
    wire_format: str  # "systemone" | "gemini" | "openai"
    calibrated: bool = True


def _env_first(env: Mapping[str, str], *names: str) -> str:
    for name in names:
        value = env.get(name, "").strip()
        if value:
            return value
    return ""


def resolve_judge_route(env: Mapping[str, str] | None = None) -> JudgeRoute | None:
    """Resolve the active decision judge from environment variables."""
    source = os.environ if env is None else env
    preferred = source.get("VIBECLEANER_JUDGE", "").strip().lower()

    routes: dict[str, JudgeRoute | None] = {
        "jev": _jev_route(source),
        "gemini": _gemini_route(source),
        "openai": _openai_route(source),
        "clef": _clef_route(source),
        "decider": _perplexity_route(source),
        "d1": _liquid_route(source),
        "microsoft": _microsoft_route(source),
        "laya": _laya_route(source),
    }

    if preferred:
        if preferred not in routes:
            valid = ", ".join(routes)
            raise ValueError(f"Unknown VIBECLEANER_JUDGE {preferred!r}. Expected one of: {valid}.")
        return routes[preferred]

    for route in routes.values():
        if route is not None:
            return route
    return None


def _jev_route(env: Mapping[str, str]) -> JudgeRoute | None:
    key = _env_first(env, "TYPESAFE_API_KEY", "JEV_API_KEY")
    if not key:
        return None
    url = _env_first(env, "TYPESAFE_BASE_URL", "JEV_BASE_URL") or "https://api.typesafe.dev/v1/systemone"
    return JudgeRoute("jev", env.get("JEV_MODEL", "").strip() or "jev-latest", url, key, "systemone")


def _gemini_route(env: Mapping[str, str]) -> JudgeRoute | None:
    key = _env_first(env, "GEMINI_API_KEY", "GOOGLE_API_KEY")
    if not key:
        return None
    return JudgeRoute("gemini", "gemini-decision-1", "", key, "gemini")


def _openai_route(env: Mapping[str, str]) -> JudgeRoute | None:
    key = _env_first(env, "OPENAI_API_KEY")
    if not key:
        return None
    base = _env_first(env, "OPENAI_BASE_URL").rstrip("/") or "https://api.openai.com"
    model = env.get("OPENAI_DECISION_MODEL", "").strip() or "gpt-6-luna"
    return JudgeRoute("openai", model, f"{base}/v1/decisions", key, "openai", calibrated=False)


def _clef_route(env: Mapping[str, str]) -> JudgeRoute | None:
    token = _env_first(env, "CLOUDFLARE_API_TOKEN")
    account = _env_first(env, "CLOUDFLARE_ACCOUNT_ID")
    if not (token and account):
        return None
    model = env.get("CLEF_MODEL", "").strip() or "clef"
    url = f"https://api.cloudflare.com/client/v4/accounts/{account}/ai/run/{model}"
    return JudgeRoute("clef", model, url, token, "systemone")


def _perplexity_route(env: Mapping[str, str]) -> JudgeRoute | None:
    key = _env_first(env, "PERPLEXITY_API_KEY")
    if not key:
        return None
    url = _env_first(env, "PERPLEXITY_BASE_URL") or "https://api.perplexity.ai/v1/decisions"
    return JudgeRoute("decider", "pplx-decider-latest", url, key, "systemone")


def _liquid_route(env: Mapping[str, str]) -> JudgeRoute | None:
    key = _env_first(env, "LIQUID_API_KEY")
    if not key:
        return None
    return JudgeRoute("d1", "d1", "https://api.liquid.ai/decisions/v1/systemone", key, "systemone")


def _microsoft_route(env: Mapping[str, str]) -> JudgeRoute | None:
    key = _env_first(env, "AZURE_OPENAI_API_KEY")
    endpoint = _env_first(env, "AZURE_OPENAI_ENDPOINT").rstrip("/")
    if not (key and endpoint):
        return None
    return JudgeRoute(
        "microsoft",
        "microsoft-decision-1",
        f"{endpoint}/providers/microsoft/v1/systemone",
        key,
        "systemone",
    )


def _laya_route(env: Mapping[str, str]) -> JudgeRoute | None:
    base = _env_first(env, "LAYA_BASE_URL").rstrip("/")
    if not base:
        return None
    key = _env_first(env, "LAYA_API_KEY")
    model = env.get("LAYA_MODEL", "").strip() or "laya"
    return JudgeRoute("laya", model, f"{base}/v1/systemone", key, "systemone")


def _format_state(auth_context: str, units: list[CodeUnit]) -> str:
    sections = [f"GLOBAL AUTH CONTEXT:\n{redact_secrets(auth_context)}"]
    for unit in units:
        sections.append(
            f"UNIT {unit.unit_id} ({unit.file}:{unit.start_line}-{unit.end_line}):\n"
            f"{redact_secrets(unit.source)}"
        )
    return "\n\n".join(sections)


def _post_json(url: str, body: dict[str, object], headers: dict[str, str], timeout_s: float = 30.0) -> dict[str, object]:
    raw = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=raw, headers={"Content-Type": "application/json", **headers}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            parsed = json.loads(resp.read().decode("utf-8"))
            return parsed if isinstance(parsed, dict) else {}
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"Decision API HTTP {exc.code} from {url}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Decision API network error for {url}: {exc.reason}") from exc


class SystemOneDecisionBackend:
    """Client for System One `noul` decision APIs (Jev, Clef, Perplexity, Liquid, Microsoft, Laya)."""

    def __init__(self, route: JudgeRoute) -> None:
        self.route = route
        self.name = route.model

    async def judge_chunk(self, auth_context: str, units: list[CodeUnit]) -> ChunkVerdict:
        state = _format_state(auth_context, units)
        questions: dict[str, dict[str, object]] = {}
        for unit in units:
            for rule_id in LAYER2_RULE_IDS:
                spec = RULES[rule_id]
                key = f"{unit.unit_id}__{LAYER2_KEY_SUFFIX[rule_id]}"
                questions[key] = {
                    "type": "noul",
                    "instructions": spec.question or spec.title,
                    "criteria": {
                        "true_description": spec.true_description or "defect present",
                        "false_description": spec.false_description or "no defect",
                    },
                }
        headers = {"Authorization": f"Bearer {self.route.api_key}"} if self.route.api_key else {}
        body = {"model": self.route.model, "state": state, "questions": questions}
        data = await asyncio.to_thread(_post_json, self.route.url, body, headers)
        return _parse_scores(data, units, field="noul")


class OpenAIDecisionBackend:
    """Client for OpenAI Decisions (`POST /v1/decisions`, predicate/probability)."""

    def __init__(self, route: JudgeRoute) -> None:
        self.route = route
        self.name = route.model
        self.calibrated = route.calibrated

    async def judge_chunk(self, auth_context: str, units: list[CodeUnit]) -> ChunkVerdict:
        state = _format_state(auth_context, units)
        questions: dict[str, dict[str, object]] = {}
        for unit in units:
            for rule_id in LAYER2_RULE_IDS:
                spec = RULES[rule_id]
                key = f"{unit.unit_id}__{LAYER2_KEY_SUFFIX[rule_id]}"
                questions[key] = {
                    "type": "predicate",
                    "instructions": spec.question or spec.title,
                }
        headers = {"Authorization": f"Bearer {self.route.api_key}"}
        body = {"model": self.route.model, "input": state, "questions": questions}
        data = await asyncio.to_thread(_post_json, self.route.url, body, headers)
        return _parse_scores(data, units, field="probability")


def _parse_scores(data: dict[str, object], units: list[CodeUnit], *, field: str) -> ChunkVerdict:
    answers = data.get("answers") or data.get("results") or data.get("decisions") or {}
    if not isinstance(answers, dict):
        answers = {}
    scores: dict[str, dict[str, float]] = {}
    for unit in units:
        unit_scores: dict[str, float] = {}
        for rule_id in LAYER2_RULE_IDS:
            key = f"{unit.unit_id}__{LAYER2_KEY_SUFFIX[rule_id]}"
            entry = answers.get(key)
            val = entry.get(field) if isinstance(entry, dict) else entry
            if isinstance(val, (int, float)) and not isinstance(val, bool):
                unit_scores[rule_id] = max(0.01, min(0.99, float(val)))
        scores[unit.unit_id] = unit_scores
    return ChunkVerdict(scores=scores, module_risk={})
