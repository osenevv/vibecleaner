"""Layer 2: chunk code units and score them with the Decisions API or a heuristic."""

from __future__ import annotations

import asyncio
import logging
import os
import re
from dataclasses import dataclass
from typing import Any, Protocol

from vibeguard.cache import GEMINI_MODEL, OFFLINE_MODEL, DecisionCache
from vibeguard.models import (
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
)

log = logging.getLogger(__name__)

DECISION_MODEL = GEMINI_MODEL
_QUESTIONS_PER_UNIT = len(LAYER2_RULE_IDS) + 1
_MAX_MODULES_PER_REQUEST = max(1, 1000 // _QUESTIONS_PER_UNIT)
_SUFFIX_TO_RULE = {suffix: rule_id for rule_id, suffix in LAYER2_KEY_SUFFIX.items()}

_MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE", "ACTION", "TOOL"}
_MUTATING_CALL = re.compile(
    r"(\.insert\s*\(|\.update\s*\(|\.delete\s*\(|\.upsert\s*\(|"
    r"\bstripe\b|\bopenai\b|"
    r"requests\.(?:post|put|patch|delete)\s*\(|"
    r"httpx\.(?:post|put|patch|delete)\s*\()",
    re.IGNORECASE,
)
_ROUTE_DECORATOR = re.compile(
    r"@(?:\w+\.)?(?:get|post|put|patch|delete|route|api_route)\b|"
    r"export\s+(?:async\s+)?function\s+(?:GET|POST|PUT|PATCH|DELETE)\b|"
    r"\b(?:app|router)\.(?:get|post|put|patch|delete)\s*\(|"
    r"""['\"]use server['\"]""",
    re.IGNORECASE,
)
_MUTATING_DECORATOR = re.compile(
    r"@(?:\w+\.)?(?:post|put|patch|delete)\b|"
    r"export\s+(?:async\s+)?function\s+(?:POST|PUT|PATCH|DELETE)\b|"
    r"\b(?:app|router)\.(?:post|put|patch|delete)\s*\(|"
    r"""['\"]use server['\"]""",
    re.IGNORECASE,
)
_LOCAL_AUTH = re.compile(
    r"(Depends\(\s*(?:get_current_user|current_user|require_user|require_auth|"
    r"auth_required|get_current_active_user)\b|"
    r"get_current_user|getServerSession|currentUser\b|"
    r"supabase\.auth\.getUser|auth\.getUser|"
    r"\bauth\(\s*\)|"
    r"req\.user\b|request\.user\b|"
    r"verifyToken|verify_token|"
    r"requireAuth|require_auth|requireUser|login_required|"
    r"if\s+not\s+session\b|if\s+session\s+is\s+None|if\s*\(\s*!session\b|"
    r"session\.user\b|getSession\s*\()",
    re.IGNORECASE,
)
_AUTH_HINT = re.compile(
    r"(matcher|middleware|Depends\s*\(|dependencies|get_current_user|getServerSession|\bauth\b)",
    re.IGNORECASE,
)
_QUOTED = re.compile(r"""['\"]([^'\"]+)['\"]""")
_PREFIX = re.compile(r"""prefix\s*=\s*['\"]([^'\"]+)['\"]""")
_DEPENDS_LIST = re.compile(r"dependencies\s*=\s*\[[^\]]*Depends\s*\(", re.IGNORECASE)

_FIELD_ALT = (
    r"user_id|userId|org_id|orgId|role|isAdmin|is_admin|price|amount|total"
)
_CLIENT_ATTR = re.compile(
    rf"(?:req\.body|request\.body|body|payload|params|data|query|formData)"
    rf"\s*\.\s*({_FIELD_ALT})\b"
)
_CLIENT_INDEX = re.compile(
    rf"(?:req\.body|request\.body|body|payload|params|data|query)"
    rf"\s*\[\s*['\"]({_FIELD_ALT})['\"]\s*\]"
)
_CLIENT_ASSIGN = re.compile(
    rf"\b({_FIELD_ALT})\s*=\s*(?:"
    rf"(?:await\s+)?(?:request|req)\.json\(\)"
    rf"|(?:body|payload|params|data|query|formData)\s*(?:\.get\s*\(|\[|\.)"
    rf")"
)
_CLIENT_FORM = re.compile(rf"formData\.get\(\s*['\"]({_FIELD_ALT})['\"]\s*\)")
_MONEY_FIELDS = {"price", "amount", "total"}
_IDENTITY_FIELDS = {"user_id", "userId", "org_id", "orgId", "role", "isAdmin", "is_admin"}
_MONEY_SINK = re.compile(
    r"(stripe|PaymentIntent|paymentIntents|\.insert\s*\(|\.update\s*\(|\bcharge\b)",
    re.IGNORECASE,
)
_QUERY_SINK = re.compile(
    r"(\.eq\s*\(|\.match\s*\(|\.filter\s*\(|\.insert\s*\(|\.update\s*\(|\bWHERE\b)",
    re.IGNORECASE,
)
_SESSION_BIND = re.compile(
    r"(session\.user|current_user\.|auth\.uid\s*\(|token\[['\"]sub['\"]\]|user\.id\b)",
    re.IGNORECASE,
)
_IO_CALL = re.compile(
    r"(await\s+|\.execute\s*\(|\.query\s*\(|\bfetch\s*\(|requests\.|"
    r"supabase\.from|prisma\.|httpx\.)"
)
_LOOP_OPEN = re.compile(r"^(?:async\s+)?(?:for|while)\b")
_UNBOUNDED_SQL = re.compile(r"select\s+\*\s+from\b", re.IGNORECASE)
_UNBOUNDED_SELECT = re.compile(r"""\.select\(\s*['\"]?\*['\"]?\s*\)""")
_FIND_MANY = re.compile(r"findMany\s*\(")
_HAS_LIMIT = re.compile(r"(\blimit\b|\.limit\s*\(|\.range\s*\(|\btake\s*:)", re.IGNORECASE)
_RAW_INPUT = re.compile(
    r"(:\s*dict\b|:\s*Any\b|:\s*Dict\b|:\s*Mapping\b|"
    r"request\.json\(\)|await\s+req\.json\(\)|await\s+request\.json\(\)|"
    r"\breq\.body\b|\brequest\.body\b|\bformData\b)"
)
_SCHEMA_OK = re.compile(
    r"(BaseModel|(?<!JSON)\.parse\s*\(|\.safeParse\s*\(|z\.object\s*\(|TypeAdapter\s*\()"
)
_DEF_HEAD = re.compile(r"(?:async\s+def|def|function)\s+\w+\s*\(")
_ANN = re.compile(r":\s*([A-Za-z_][\w]*)")
_INTERP_EXPR = re.compile(r"\{([^{}]+)\}|\$\{([^{}]+)\}")
_UNTRUSTED_EXPR = re.compile(
    r"(user_|user\.|req\.|request\.|\bprompt\b|\bbody\b|\bargs\b|\binput\b|\bmessage\b)",
    re.IGNORECASE,
)
_NON_MODEL = {
    "Request",
    "Response",
    "HTTPException",
    "Session",
    "WebSocket",
    "UploadFile",
    "FormData",
    "dict",
    "Dict",
    "Any",
    "Mapping",
    "str",
    "int",
    "float",
    "bool",
    "bytes",
    "None",
    "list",
    "List",
    "Optional",
}
_USES_FIELDS = re.compile(
    r"(\[\s*['\"][A-Za-z_][\w]*['\"]\s*\]|"
    r"(?:body|data|payload|query|params|formData)\s*\.\s*[A-Za-z_]|"
    r"\{\s*[A-Za-z_][\w]*\s*(?:,[^}]*)?\}\s*=\s*[^;\n]{0,60}"
    r"(?:json\(\)|body|payload|params|formData))"
)
_STUB_WORD = re.compile(
    r"(\bmock\b|\bdummy\b|\bfake\b|\blorem\b|\bTODO\b|"
    r"\bnot implemented\b|\bNotImplemented\b|\bplaceholder\b)",
    re.IGNORECASE,
)
_FAKE_SUCCESS = re.compile(r"""return\s+\{\s*['\"]success['\"]\s*:\s*(?:True|true)\s*\}""")
_REAL_WORK = re.compile(
    r"(await\s+|\.execute\s*\(|\bfetch\s*\(|requests\.|supabase\.|prisma\.|"
    r"\.insert\s*\(|\.update\s*\(|\.delete\s*\(|\.query\s*\()"
)
_SYSTEM_FSTRING = re.compile(
    r"system(?:_prompt|_message)?\s*=\s*f['\"][^'\"]*\{|"
    r"system(?:_prompt|_message)?\s*=\s*`[^`]*\$\{|"
    r"content\s*[:=]\s*f['\"][^'\"]*\{|"
    r"content\s*[:=]\s*`[^`]*\$\{"
)
_SYSTEM_ROLE = re.compile(r"""role\s*[:=]\s*['\"]system['\"]""", re.IGNORECASE)
_EXEC_SINKS = (
    re.compile(r"subprocess\.(?:run|call|Popen|check_output|check_call)\s*\([^)]{0,180}", re.IGNORECASE),
    re.compile(r"os\.system\s*\([^)]{0,180}", re.IGNORECASE),
    re.compile(r"\beval\s*\([^)]{0,180}"),
    re.compile(r"(?<![\w.])exec\s*\([^)]{0,120}"),
    re.compile(r"(?:fs\.writeFile(?:Sync)?|writeFile(?:Sync)?)\s*\([^)]{0,180}"),
)
_SQL_EXECUTE = re.compile(r"""\.execute\(\s*(?:f['\"]|`)""", re.IGNORECASE)
_UNTRUSTED_FRAGMENT = re.compile(
    r"(f['\"]|`[^`]*\$\{|\$\{|user_|user\.|req\.|request\.|\bprompt\b|\binput\b|\bbody\b|\bargs\b)",
    re.IGNORECASE,
)


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


@dataclass
class ChunkVerdict:
    scores: dict[str, dict[str, float]]
    severity: dict[str, float]
    input_tokens: int


class DecisionBackend(Protocol):
    name: str

    async def judge_chunk(self, auth_context: str, units: list[CodeUnit]) -> ChunkVerdict:
        """Score one chunk. ``scores`` maps unit_id -> rule_id -> noul."""


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
        + unit.source
        + "\n</source>\n"
        + f"[/{unit.label}]"
    )


def _questions_for(label: str) -> dict[str, dict[str, Any]]:
    questions: dict[str, dict[str, Any]] = {}
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


def build_payload(auth_context: str, units: list[CodeUnit]) -> dict[str, Any]:
    """Decisions API body: ``{model, input, questions}``."""
    body = "\n\n".join(format_module(unit) for unit in units)
    questions: dict[str, dict[str, Any]] = {}
    for unit in units:
        questions.update(_questions_for(unit.label))
    return {
        "model": DECISION_MODEL,
        "input": "[GLOBAL_AUTH_CONTEXT]\n" + auth_context + "\n\n" + body,
        "questions": questions,
    }


def units_to_skip(units: list[CodeUnit], layer1_findings: list[Finding]) -> set[str]:
    """Unit ids whose span contains a Layer 1 finding (do not spend Layer 2 tokens)."""
    skipped: set[str] = set()
    layer1 = [finding for finding in layer1_findings if finding.layer == 1]
    if not layer1:
        return skipped
    for unit in units:
        for finding in layer1:
            if finding.file == unit.file and unit.contains_line(finding.line):
                skipped.add(unit.unit_id)
                break
    return skipped


def _lookup(obj: Any, key: str) -> Any:
    """Read ``key`` from a dict-style or attribute-style response object."""
    if obj is None:
        return None
    if isinstance(obj, dict):
        return obj.get(key)
    getter = getattr(obj, "get", None)
    if callable(getter):
        try:
            value = getter(key)
        except Exception:
            value = None
        else:
            if value is not None:
                return value
    return getattr(obj, key, None)


def _as_float(value: Any) -> float | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        number = float(value)
    elif isinstance(value, str):
        try:
            number = float(value)
        except ValueError:
            return None
    else:
        return None
    if number != number or number in (float("inf"), float("-inf")):
        return None
    return number


def _clamp_probability(value: float) -> float:
    return min(0.99, max(0.01, value))


def _iter_answers(answers: Any) -> list[tuple[str, Any]]:
    if answers is None:
        return []
    if isinstance(answers, dict):
        return [(str(key), value) for key, value in answers.items()]
    items = getattr(answers, "items", None)
    if callable(items):
        try:
            return [(str(key), value) for key, value in items()]
        except Exception:
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
    if isinstance(exc, (TimeoutError, asyncio.TimeoutError)):
        return True
    return "timeout" in type(exc).__name__.lower()


def _is_retryable(exc: BaseException) -> bool:
    if isinstance(exc, (asyncio.CancelledError, KeyboardInterrupt)):
        return False
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


def _verdict_from_response(result: Any, units: list[CodeUnit], model_input: str) -> ChunkVerdict:
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
        client: Any = None,
        *,
        max_attempts: int = 3,
        base_delay: float = 0.5,
    ) -> None:
        self.api_key = api_key
        self._client = client
        self._max_attempts = max(1, max_attempts)
        self._base_delay = max(0.0, base_delay)

    def _ensure_client(self) -> Any:
        if self._client is None:
            from google import genai

            self._client = genai.Client(
                api_key=self.api_key,
                http_options={"api_version": "v1beta"},
            )
        return self._client

    async def judge_chunk(self, auth_context: str, units: list[CodeUnit]) -> ChunkVerdict:
        payload = build_payload(auth_context, units)
        result = await self._create_with_retry(payload)
        return _verdict_from_response(result, units, payload["input"])

    async def _create_with_retry(self, payload: dict[str, Any]) -> Any:
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
            except asyncio.CancelledError:
                raise
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


class OfflineHeuristicBackend:
    """Deterministic zero-network fallback. Prefers missing a bug over a false alarm."""

    name = OFFLINE_MODEL

    async def judge_chunk(self, auth_context: str, units: list[CodeUnit]) -> ChunkVerdict:
        scores: dict[str, dict[str, float]] = {}
        severity: dict[str, float] = {}
        for unit in units:
            unit_scores = {
                "D3.missing_auth": _score_missing_auth(unit, auth_context),
                "D4.idor_or_price_trust": _score_idor(unit),
                "D5.prompt_injection": _score_prompt_injection(unit),
                "D6b.hardcoded_mock_stub": _score_mock(unit),
                "D7a.n_plus_one_loop": _score_n_plus_one(unit),
                "D7b.missing_boundary_schema": _score_boundary(unit),
            }
            scores[unit.unit_id] = unit_scores
            severity[unit.unit_id] = _severity_from_scores(unit_scores)
        return ChunkVerdict(scores=scores, severity=severity, input_tokens=0)


def _score_missing_auth(unit: CodeUnit, auth_context: str) -> float:
    method = (unit.http_method or "").upper()
    mutates = method in _MUTATING_METHODS or bool(_MUTATING_CALL.search(unit.source))
    if not mutates or not _is_entrypoint(unit):
        return 0.05
    if _LOCAL_AUTH.search(unit.source) or _auth_context_covers(unit.route_path, auth_context):
        return 0.05
    if method in _MUTATING_METHODS or unit.kind in {"route", "tool"} or _MUTATING_DECORATOR.search(unit.source):
        return 0.93
    return 0.66


def _is_entrypoint(unit: CodeUnit) -> bool:
    method = (unit.http_method or "").upper()
    if unit.kind in {"route", "tool"} or unit.route_path or method in _MUTATING_METHODS | {"GET", "HEAD"}:
        return True
    return bool(_ROUTE_DECORATOR.search(unit.source))


def _auth_context_covers(route_path: str | None, auth_context: str) -> bool:
    if not route_path or not auth_context.strip() or not _AUTH_HINT.search(auth_context):
        return False
    path = _normalize_path(route_path)
    for pattern in _QUOTED.findall(auth_context):
        if pattern != "*" and not pattern.startswith("/"):
            continue
        if _path_covered(pattern, path):
            return True
    if _DEPENDS_LIST.search(auth_context) or re.search(r"Depends\s*\(", auth_context):
        for prefix in _PREFIX.findall(auth_context):
            norm = _normalize_path(prefix)
            if path == norm or path.startswith(norm + "/"):
                return True
    return False


def _normalize_path(path: str) -> str:
    text = path.strip()
    if not text.startswith("/"):
        text = "/" + text
    if len(text) > 1:
        text = text.rstrip("/")
    return text


def _path_covered(pattern: str, path: str) -> bool:
    if pattern in {"*", "/*"}:
        return True
    if pattern.endswith("*"):
        prefix = re.sub(r":[A-Za-z_][A-Za-z0-9_]*$", "", pattern[:-1]).rstrip("/")
        prefix = _normalize_path(prefix) if prefix else "/"
        if prefix == "/":
            return True
        return path == prefix or path.startswith(prefix + "/")
    pattern_parts = [part for part in pattern.split("/") if part]
    path_parts = [part for part in path.split("/") if part]
    if len(pattern_parts) != len(path_parts):
        return False
    for pattern_part, path_part in zip(pattern_parts, path_parts):
        if pattern_part.startswith(":"):
            continue
        if pattern_part != path_part:
            return False
    return True


def _client_fields(source: str) -> set[str]:
    found: set[str] = set()
    for pattern in (_CLIENT_ATTR, _CLIENT_INDEX, _CLIENT_ASSIGN, _CLIENT_FORM):
        found.update(pattern.findall(source))
    return found


def _score_idor(unit: CodeUnit) -> float:
    fields = _client_fields(unit.source)
    if not fields:
        return 0.05
    money = bool(fields & _MONEY_FIELDS) and bool(_MONEY_SINK.search(unit.source))
    identity = bool(fields & _IDENTITY_FIELDS) and bool(_QUERY_SINK.search(unit.source))
    if not money and not identity:
        return 0.05
    if money:
        return 0.94
    if _SESSION_BIND.search(unit.source):
        return 0.12
    return 0.90


def _score_prompt_injection(unit: CodeUnit) -> float:
    source = unit.source
    if _system_interpolates_untrusted(source):
        return 0.93
    if _untrusted_sql(source):
        return 0.91
    for pattern in _EXEC_SINKS:
        match = pattern.search(source)
        if match and _UNTRUSTED_FRAGMENT.search(match.group(0)):
            return 0.91
    return 0.05


def _untrusted_sql(source: str) -> bool:
    for match in _SQL_EXECUTE.finditer(source):
        window = source[match.start() : match.start() + 240]
        if not re.search(r"\b(?:SELECT|INSERT|UPDATE|DELETE)\b", window, re.IGNORECASE):
            continue
        if re.search(r"\{[A-Za-z_]", window) or "${" in window:
            return True
    return False


def _system_interpolates_untrusted(source: str) -> bool:
    for match in _SYSTEM_FSTRING.finditer(source):
        window = source[match.start() : match.start() + 240]
        if _window_has_untrusted_expr(window):
            return True
    if not _SYSTEM_ROLE.search(source):
        return False
    for match in _INTERP_EXPR.finditer(source):
        expr = match.group(1) or match.group(2) or ""
        if not _UNTRUSTED_EXPR.search(expr):
            continue
        around = source[max(0, match.start() - 180) : match.end() + 180]
        if _SYSTEM_ROLE.search(around):
            return True
    return False


def _window_has_untrusted_expr(window: str) -> bool:
    for match in _INTERP_EXPR.finditer(window):
        expr = match.group(1) or match.group(2) or ""
        if _UNTRUSTED_EXPR.search(expr):
            return True
    return False


def _score_mock(unit: CodeUnit) -> float:
    source = unit.source
    if _REAL_WORK.search(source):
        return 0.05
    if _FAKE_SUCCESS.search(source):
        return 0.91
    if _STUB_WORD.search(source) and re.search(r"\breturn\b", source):
        return 0.90
    lines = [
        line.strip()
        for line in source.splitlines()
        if line.strip() and not line.strip().startswith(("#", "@", "//"))
    ]
    if lines and lines[-1] == "pass" and "return" not in source:
        return 0.86
    return 0.05


def _score_n_plus_one(unit: CodeUnit) -> float:
    source = unit.source
    loop_io = _io_inside_loop(source)
    unbounded = False
    if _UNBOUNDED_SQL.search(source) or _UNBOUNDED_SELECT.search(source):
        unbounded = not bool(_HAS_LIMIT.search(source))
    if _FIND_MANY.search(source) and not _HAS_LIMIT.search(source):
        unbounded = True
    if loop_io:
        return 0.92
    if unbounded:
        return 0.84
    return 0.05


def _io_inside_loop(source: str) -> bool:
    loop_indent: int | None = None
    for raw_line in source.splitlines():
        line = raw_line.expandtabs(4)
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "//")):
            continue
        indent = len(line) - len(line.lstrip(" "))
        if loop_indent is not None and indent <= loop_indent:
            loop_indent = None
        if _LOOP_OPEN.match(stripped):
            if _IO_CALL.search(stripped):
                return True
            loop_indent = indent
            continue
        if loop_indent is not None and _IO_CALL.search(stripped):
            return True
    for match in re.finditer(r"\.(?:map|forEach)\s*\(", source):
        before = source[max(0, match.start() - 40) : match.start()]
        if "Promise.all" in before:
            continue
        window = source[match.start() : match.start() + 500]
        if _IO_CALL.search(window):
            return True
    return False


def _score_boundary(unit: CodeUnit) -> float:
    if not _is_entrypoint(unit):
        return 0.05
    source = unit.source
    if _SCHEMA_OK.search(source) or _has_model_param(source):
        return 0.05
    if not _RAW_INPUT.search(source):
        return 0.05
    if _USES_FIELDS.search(source):
        return 0.88
    return 0.62


def _has_model_param(source: str) -> bool:
    signature = _first_signature(source)
    if signature is None:
        return False
    for name in _ANN.findall(signature):
        if name[:1].isupper() and name not in _NON_MODEL:
            return True
    return False


def _first_signature(source: str) -> str | None:
    match = _DEF_HEAD.search(source)
    if match is None:
        return None
    depth = 1
    index = match.end()
    while index < len(source) and depth:
        char = source[index]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        index += 1
    if depth:
        return None
    return source[match.end() : index - 1]


def _severity_from_scores(scores: dict[str, float]) -> float:
    security = max(
        scores.get("D3.missing_auth", 0.0),
        scores.get("D4.idor_or_price_trust", 0.0),
        scores.get("D5.prompt_injection", 0.0),
    )
    slop = max(
        scores.get("D6b.hardcoded_mock_stub", 0.0),
        scores.get("D7a.n_plus_one_loop", 0.0),
        scores.get("D7b.missing_boundary_schema", 0.0),
    )
    if security >= 0.75:
        return 2.0
    if slop >= 0.75:
        return 1.0
    return 0.1


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
    text = unit.source.strip()
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
    stats = JudgeStats()
    skip = set(skip_unit_ids)
    stats.units_skipped_layer1 = sum(1 for unit in ctx.units if unit.unit_id in skip)
    if backend is None:
        stats.mode = "disabled"
        return [], stats
    stats.mode = _mode_name(backend)
    cache.model = backend.name

    cached: dict[str, dict[str, float]] = {}
    pending: list[CodeUnit] = []
    for unit in ctx.units:
        if unit.unit_id in skip:
            continue
        hit = cache.get(unit, ctx.auth_context)
        if hit is None:
            pending.append(unit)
        else:
            cached[unit.unit_id] = hit
    stats.cache_hits = len(cached)

    chunks = chunk_units(pending, ctx.auth_context) if pending else []
    semaphore = asyncio.Semaphore(max(1, concurrency))

    async def run_chunk(chunk: list[CodeUnit]) -> tuple[list[CodeUnit], ChunkVerdict | None, str | None]:
        async with semaphore:
            try:
                verdict = await backend.judge_chunk(ctx.auth_context, chunk)
            except asyncio.CancelledError:
                raise
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
            if missing:
                stats.errors.append(
                    f"incomplete scores for {unit.unit_id}: missing {', '.join(sorted(missing))}"
                )
            else:
                cache.put(unit, ctx.auth_context, scores)
            if scores:
                judged[unit.unit_id] = scores
    stats.units_judged = len(judged)

    findings: list[Finding] = []
    for unit in ctx.units:
        scores = judged.get(unit.unit_id)
        if not scores:
            continue
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
    """``auto`` uses live when an API key is set, otherwise the offline heuristic."""
    normalized = mode.strip().lower()
    if normalized not in {"auto", "live", "offline", "off"}:
        raise DecisionAPIError(
            f"Unknown decision mode {mode!r}. Expected auto, live, offline, or off."
        )
    if normalized == "off":
        return None
    if normalized == "offline":
        return OfflineHeuristicBackend()
    api_key = _api_key()
    if normalized == "auto":
        if api_key:
            return GeminiDecisionBackend(api_key=api_key)
        return OfflineHeuristicBackend()
    if not api_key:
        raise DecisionAPIError(
            "mode 'live' requires GEMINI_API_KEY or GOOGLE_API_KEY to call gemini-decision-1. "
            "Export one of those, or rerun with --mode offline."
        )
    return GeminiDecisionBackend(api_key=api_key)


def _api_key() -> str | None:
    for name in ("GEMINI_API_KEY", "GOOGLE_API_KEY"):
        value = os.environ.get(name, "").strip()
        if value:
            return value
    return None
