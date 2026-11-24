"""Layer 2: chunk code units and score them with the Decisions API or a heuristic."""

from __future__ import annotations

import asyncio
import logging
import re
from collections.abc import Mapping
from typing import Literal, Protocol, TypedDict

from vibecleaner.cache import GEMINI_MODEL, OFFLINE_MODEL, ChunkVerdict, DecisionCache, _finite_number
from vibecleaner.models import (
    DEFAULT_THRESHOLD,
    LAYER2_KEY_SUFFIX,
    LAYER2_RULE_IDS,
    RULES,
    SEVERITY_QUESTION_CRITERIA,
    CodeUnit,
    Finding,
    JudgeStats,
    RuleSpec,
    ScanContext,
    Severity,
)
from vibecleaner.offline_heuristics import OfflineHeuristicBackend, module_risk_from_scores
from vibecleaner.redact import redact_secrets
from vibecleaner.settings import api_key, genai_client

log = logging.getLogger(__name__)

DECISION_MODEL = GEMINI_MODEL
_QUESTIONS_PER_UNIT = len(LAYER2_RULE_IDS) + 1
_MAX_MODULES_PER_REQUEST = max(1, 1000 // _QUESTIONS_PER_UNIT)
_SUFFIX_TO_RULE = {suffix: rule_id for rule_id, suffix in LAYER2_KEY_SUFFIX.items()}

class DecisionAPIError(RuntimeError):
    """Non-retryable Decisions API failure, or live mode with no API key."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        code: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code


class _NoulCriteria(TypedDict):
    true_description: str
    false_description: str


class _NoulQuestion(TypedDict):
    type: Literal["noul"]
    instructions: str
    criteria: _NoulCriteria


class _ScoreQuestion(TypedDict):
    type: Literal["score"]
    instructions: str
    criteria: list[str]


_Question = _NoulQuestion | _ScoreQuestion


class _DecisionPayload(TypedDict):
    model: str
    input: str
    questions: dict[str, _Question]


class _DecisionCreate(Protocol):
    async def create(
        self,
        *,
        model: str,
        input: str,
        questions: Mapping[str, _Question],
    ) -> object: ...


class _DecisionAio(Protocol):
    decisions: _DecisionCreate


class _DecisionClient(Protocol):
    aio: _DecisionAio


class DecisionBackend(Protocol):
    name: str

    async def judge_chunk(self, auth_context: str, units: list[CodeUnit]) -> ChunkVerdict:
        """Score one chunk. ``scores`` maps unit_id -> rule_id -> noul."""


def require_threshold(threshold: float) -> float:
    """Reject cutoffs that noul can never cross.

    gemini-decision-1 returns a probability in 0.01..0.99. A cutoff of 0 flags
    every scored rule, and a cutoff of 1 flags none, so neither is a real gate.
    """
    if isinstance(threshold, bool):
        raise DecisionAPIError("threshold must be a probability between 0.01 and 0.99")
    try:
        value = float(threshold)
    except (TypeError, ValueError) as exc:
        raise DecisionAPIError("threshold must be a probability between 0.01 and 0.99") from exc
    number = _finite_number(value)
    if number is None or not 0.01 <= number <= 0.99:
        raise DecisionAPIError(
            f"threshold {threshold} is outside 0.01..0.99. "
            "noul never returns 0 or 1, so a cutoff outside that range cannot fail the scan."
        )
    return number


def estimate_tokens(text: str) -> int:
    """Rough token count used only for chunking (about 4 characters per token)."""
    if not text:
        return 0
    return len(text) // 4


def format_module(unit: CodeUnit) -> str:
    """Render one unit as a labeled block the decision model can cite."""
    meta = [
        f"[{unit.label}]",
        f"file={unit.file}",
        f"lines={unit.start_line}-{unit.end_line}",
        f"kind={unit.kind}",
    ]
    if unit.http_method:
        meta.append(f"method={unit.http_method}")
    if unit.route_path:
        meta.append(f"path={unit.route_path}")
    return (
        " ".join(meta)
        + "\n<source>\n"
        + redact_secrets(unit.source)
        + "\n</source>\n"
        + f"[/{unit.label}]"
    )


def _questions_for(label: str) -> dict[str, _Question]:
    questions: dict[str, _Question] = {}
    for rule_id in LAYER2_RULE_IDS:
        spec = RULES[rule_id]
        key = f"{label}__{LAYER2_KEY_SUFFIX[rule_id]}"
        questions[key] = {
            "type": "noul",
            "instructions": (spec.question or "").format(module=label),
            "criteria": {
                "true_description": spec.true_description or "",
                "false_description": spec.false_description or "",
            },
        }
    questions[f"{label}__severity"] = {
        "type": "score",
        "instructions": f"Rate the overall production risk of {label}.",
        "criteria": list(SEVERITY_QUESTION_CRITERIA),
    }
    return questions


def _question_token_cost() -> int:
    return estimate_tokens(_stable_question_blob())


def _stable_question_blob() -> str:
    return repr(_questions_for("MOD_00"))


def chunk_units(
    units: list[CodeUnit],
    auth_context: str,
    max_tokens: int = 30_000,
    max_modules: int = 30,
) -> list[list[CodeUnit]]:
    """Greedy chunks that preserve order and restart labels at MOD_01.

    A single unit that is already over ``max_tokens`` is emitted alone.
    """
    if not units:
        return []
    limit = max(1, min(max_modules, _MAX_MODULES_PER_REQUEST))
    question_tokens = _question_token_cost()
    overhead = estimate_tokens("[GLOBAL_AUTH_CONTEXT]\n" + auth_context + "\n\n")
    chunks: list[list[CodeUnit]] = []
    current: list[CodeUnit] = []
    current_tokens = overhead

    def cost_of(unit: CodeUnit) -> int:
        return estimate_tokens(format_module(unit)) + question_tokens

    for unit in units:
        unit.label = f"MOD_{len(current) + 1:02d}"
        cost = cost_of(unit)
        over_budget = bool(current) and (len(current) >= limit or current_tokens + cost > max_tokens)
        if over_budget:
            chunks.append(current)
            current = []
            current_tokens = overhead
            unit.label = "MOD_01"
            cost = cost_of(unit)
        current.append(unit)
        current_tokens += cost
    if current:
        chunks.append(current)
    return chunks


def build_payload(auth_context: str, units: list[CodeUnit]) -> _DecisionPayload:
    """Decisions API body: ``{model, input, questions}``."""
    body = "\n\n".join(format_module(unit) for unit in units)
    questions: dict[str, _Question] = {}
    for unit in units:
        questions.update(_questions_for(unit.label))
    return {
        "model": DECISION_MODEL,
        "input": "[GLOBAL_AUTH_CONTEXT]\n" + redact_secrets(auth_context) + "\n\n" + body,
        "questions": questions,
    }


def units_to_skip(units: list[CodeUnit], layer1_findings: list[Finding]) -> set[str]:
    """Skip a unit only when a critical Layer 1 finding already fails the build."""
    skipped: set[str] = set()
    layer1 = [
        finding
        for finding in layer1_findings
        if finding.layer == 1 and finding.severity == Severity.CRITICAL
    ]
    if not layer1:
        return skipped
    for unit in units:
        for finding in layer1:
            if finding.file == unit.file and unit.contains_line(finding.line):
                skipped.add(unit.unit_id)
                break
    return skipped


def _lookup(obj: object, key: str) -> object:
    """Read ``key`` from a dict-style or attribute-style response object."""
    if obj is None:
        return None
    if isinstance(obj, dict):
        return obj.get(key)
    getter = getattr(obj, "get", None)
    if callable(getter):
        try:
            value = getter(key)
        except (AttributeError, KeyError, TypeError):
            value = None
        else:
            if value is not None:
                return value
    return getattr(obj, key, None)


def _as_float(value: object) -> float | None:
    if isinstance(value, str):
        try:
            value = float(value)
        except ValueError:
            return None
    return _finite_number(value)


def _clamp_probability(value: float) -> float:
    return min(0.99, max(0.01, value))


def _iter_answers(answers: object) -> list[tuple[str, object]]:
    if answers is None:
        return []
    if isinstance(answers, dict):
        return [(str(key), value) for key, value in answers.items()]
    items = getattr(answers, "items", None)
    if callable(items):
        try:
            return [(str(key), value) for key, value in items()]
        except (AttributeError, KeyError, TypeError):
            return []
    return []


def _status_code(exc: BaseException) -> int | None:
    for attr in ("status_code", "code"):
        value = getattr(exc, attr, None)
        if isinstance(value, int):
            return value
    response = getattr(exc, "response", None) or getattr(exc, "raw_response", None)
    if response is not None:
        value = getattr(response, "status_code", None)
        if isinstance(value, int):
            return value
    return None


def _error_code(exc: BaseException) -> str | None:
    status = getattr(exc, "status", None)
    if isinstance(status, str) and status and not status.isdigit():
        return status
    body = getattr(exc, "body", None)
    if isinstance(body, str):
        match = re.search(r'"code"\s*:\s*"([^"]+)"', body)
        if match:
            return match.group(1)
    return None


def _is_timeout(exc: BaseException) -> bool:
    if isinstance(exc, TimeoutError):
        return True
    return "timeout" in type(exc).__name__.lower()


def _is_retryable(exc: BaseException) -> bool:
    if _is_timeout(exc):
        return True
    status = _status_code(exc)
    if status is None:
        return False
    return status == 429 or status >= 500


def _to_api_error(exc: BaseException, attempts: int) -> DecisionAPIError:
    status = _status_code(exc)
    prefix = f"Decisions API failed after {attempts} attempts" if attempts > 1 else "Decisions API error"
    if status is not None:
        prefix = f"{prefix} (HTTP {status})"
    return DecisionAPIError(f"{prefix}: {exc}", status_code=status, code=_error_code(exc))


def _verdict_from_response(result: object, units: list[CodeUnit], model_input: str) -> ChunkVerdict:
    answers = _lookup(result, "answers")
    pairs = _iter_answers(answers)
    if not pairs:
        raise DecisionAPIError("Decisions API returned no answers")
    by_label = {unit.label: unit for unit in units}
    scores: dict[str, dict[str, float]] = {unit.unit_id: {} for unit in units}
    severity: dict[str, float] = {}
    for key, answer in pairs:
        if "__" not in key:
            continue
        label, suffix = key.split("__", 1)
        unit = by_label.get(label)
        if unit is None:
            continue
        if suffix == "severity":
            score = _as_float(_lookup(answer, "score"))
            if score is not None:
                severity[unit.unit_id] = score
            continue
        rule_id = _SUFFIX_TO_RULE.get(suffix)
        if rule_id is None:
            continue
        noul = _as_float(_lookup(answer, "noul"))
        if noul is None:
            continue
        scores[unit.unit_id][rule_id] = _clamp_probability(noul)
    usage = _lookup(result, "usage")
    tokens = _as_float(_lookup(usage, "total_input_tokens")) if usage is not None else None
    input_tokens = int(tokens) if tokens is not None and tokens >= 0 else estimate_tokens(model_input)
    return ChunkVerdict(scores=scores, severity=severity, input_tokens=input_tokens)


class GeminiDecisionBackend:
    """Live ``gemini-decision-1`` backend. Retries 429, 5xx, and timeouts."""

    name = DECISION_MODEL

    def __init__(
        self,
        api_key: str,
        client: _DecisionClient | None = None,
        *,
        max_attempts: int = 3,
        base_delay: float = 0.5,
    ) -> None:
        self.api_key = api_key
        self._client = client
        self._max_attempts = max(1, max_attempts)
        self._base_delay = max(0.0, base_delay)

    def _ensure_client(self) -> _DecisionClient:
        if self._client is None:
            self._client = genai_client(self.api_key, api_version="v1beta")
        return self._client

    async def judge_chunk(self, auth_context: str, units: list[CodeUnit]) -> ChunkVerdict:
        payload = build_payload(auth_context, units)
        result = await self._create_with_retry(payload)
        return _verdict_from_response(result, units, payload["input"])

    async def _create_with_retry(self, payload: _DecisionPayload) -> object:
        client = self._ensure_client()
        delay = self._base_delay
        last: BaseException | None = None
        for attempt in range(1, self._max_attempts + 1):
            try:
                return await client.aio.decisions.create(
                    model=payload["model"],
                    input=payload["input"],
                    questions=payload["questions"],
                )
            except Exception as exc:
                last = exc
                if not _is_retryable(exc) or attempt == self._max_attempts:
                    raise _to_api_error(exc, attempt) from exc
                log.warning(
                    "Decisions API retry %s/%s after %s",
                    attempt,
                    self._max_attempts,
                    exc,
                )
                if delay:
                    await asyncio.sleep(delay)
                delay *= 2
        raise _to_api_error(last or RuntimeError("unknown decisions error"), self._max_attempts)


def _finding_message(spec: RuleSpec, unit: CodeUnit) -> str:
    parts = [spec.title, "in", unit.kind or "code"]
    if unit.http_method:
        parts.append(unit.http_method)
    if unit.route_path:
        parts.append(unit.route_path)
    sentence = " ".join(parts)
    if unit.name:
        sentence += f" ({unit.name})"
    return sentence + "."


def _snippet(unit: CodeUnit, limit: int = 500) -> str:
    text = redact_secrets(unit.source.strip())
    if len(text) <= limit:
        return text
    return text[: limit - 1] + "…"


def _mode_name(backend: DecisionBackend) -> str:
    if backend.name == DECISION_MODEL:
        return "live"
    if backend.name == OFFLINE_MODEL:
        return "offline"
    return backend.name


async def judge_async(
    ctx: ScanContext,
    backend: DecisionBackend | None,
    cache: DecisionCache,
    threshold: float = DEFAULT_THRESHOLD,
    skip_unit_ids: set[str] | frozenset[str] = frozenset(),
    concurrency: int = 4,
) -> tuple[list[Finding], JudgeStats]:
    """Judge ``ctx.units``, serving cached scores and continuing after a failed chunk."""
    threshold = require_threshold(threshold)
    stats = JudgeStats()
    skip = set(skip_unit_ids)
    stats.units_skipped_layer1 = sum(1 for unit in ctx.units if unit.unit_id in skip)
    if backend is None:
        stats.mode = "disabled"
        return [], stats
    stats.mode = _mode_name(backend)
    cache.model = backend.name
    binder = getattr(backend, "bind_catalog", None)
    if callable(binder):
        binder(list(ctx.units))

    cached: dict[str, dict[str, float]] = {}
    risks: dict[str, float] = {}
    pending: list[CodeUnit] = []
    for unit in ctx.units:
        if unit.unit_id in skip:
            continue
        hit = cache.get(unit, ctx.auth_context)
        if hit is None:
            pending.append(unit)
        else:
            cached[unit.unit_id] = hit
            stored_risk = cache.module_risk(unit, ctx.auth_context)
            if stored_risk is not None:
                risks[unit.unit_id] = stored_risk
    stats.cache_hits = len(cached)

    chunks = chunk_units(pending, ctx.auth_context) if pending else []
    semaphore = asyncio.Semaphore(max(1, concurrency))

    async def run_chunk(chunk: list[CodeUnit]) -> tuple[list[CodeUnit], ChunkVerdict | None, str | None]:
        async with semaphore:
            try:
                verdict = await backend.judge_chunk(ctx.auth_context, chunk)
            except Exception as exc:
                ids = ", ".join(unit.unit_id for unit in chunk)
                message = f"{type(exc).__name__}: {exc} [{ids}]"
                log.warning("Layer 2 chunk failed: %s", message)
                return chunk, None, message
            return chunk, verdict, None

    results = await asyncio.gather(*(run_chunk(chunk) for chunk in chunks))
    judged = dict(cached)
    expected = set(LAYER2_RULE_IDS)
    for chunk, verdict, error in results:
        stats.requests += 1
        if error or verdict is None:
            stats.errors.append(error or "empty chunk verdict")
            continue
        stats.input_tokens += verdict.input_tokens
        for unit in chunk:
            scores = verdict.scores.get(unit.unit_id, {})
            missing = expected - set(scores)
            risk = verdict.severity.get(unit.unit_id)
            if risk is None and scores:
                risk = module_risk_from_scores(scores)
            if risk is not None:
                risks[unit.unit_id] = risk
            if missing:
                stats.errors.append(
                    f"incomplete scores for {unit.unit_id}: missing {', '.join(sorted(missing))}"
                )
            else:
                cache.put(unit, ctx.auth_context, scores, module_risk=risk)
            if scores:
                judged[unit.unit_id] = scores
    stats.units_judged = len(judged)

    findings: list[Finding] = []
    for unit in ctx.units:
        scores = judged.get(unit.unit_id)
        if not scores:
            continue
        module_risk = risks.get(unit.unit_id)
        if module_risk is None:
            module_risk = module_risk_from_scores(scores)
        for rule_id in LAYER2_RULE_IDS:
            noul = scores.get(rule_id)
            if noul is None or float(noul) < threshold:
                continue
            spec = RULES[rule_id]
            findings.append(
                Finding(
                    rule_id=rule_id,
                    file=unit.file,
                    line=unit.start_line,
                    end_line=unit.end_line,
                    symbol=unit.name,
                    probability=float(noul),
                    message=_finding_message(spec, unit),
                    snippet=_snippet(unit),
                    module_risk=module_risk,
                )
            )
    return findings, stats


def judge(
    ctx: ScanContext,
    backend: DecisionBackend | None,
    cache: DecisionCache,
    threshold: float = DEFAULT_THRESHOLD,
    skip_unit_ids: set[str] | frozenset[str] = frozenset(),
    concurrency: int = 4,
) -> tuple[list[Finding], JudgeStats]:
    """Synchronous wrapper around :func:`judge_async`."""
    return asyncio.run(
        judge_async(
            ctx,
            backend,
            cache,
            threshold=threshold,
            skip_unit_ids=skip_unit_ids,
            concurrency=concurrency,
        )
    )


def select_backend(mode: str) -> DecisionBackend | None:
    """``auto`` uses live when any decision API key is set, otherwise the offline heuristic."""
    normalized = mode.strip().lower()
    if normalized not in {"auto", "live", "offline", "off"}:
        raise DecisionAPIError(
            f"Unknown decision mode {mode!r}. Expected auto, live, offline, or off."
        )
    if normalized == "off":
        return None
    if normalized == "offline":
        return OfflineHeuristicBackend()
    from vibecleaner.judge_backends import (
        OpenAIDecisionBackend,
        SystemOneDecisionBackend,
        resolve_judge_route,
    )

    try:
        route = resolve_judge_route()
    except ValueError as exc:
        raise DecisionAPIError(str(exc)) from exc
    if route is None:
        if normalized == "auto":
            return OfflineHeuristicBackend()
        raise DecisionAPIError(
            "mode 'live' requires a decision API key (TYPESAFE_API_KEY, GEMINI_API_KEY, "
            "OPENAI_API_KEY, PERPLEXITY_API_KEY, LIQUID_API_KEY, or LAYA_BASE_URL). "
            "Export one of those, or rerun with --mode offline."
        )
    if route.wire_format == "gemini":
        return GeminiDecisionBackend(api_key=route.api_key)
    if route.wire_format == "openai":
        return OpenAIDecisionBackend(route)
    return SystemOneDecisionBackend(route)
