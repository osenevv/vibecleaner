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

_MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE", "ACTION"}
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
_QUOTED = re.compile(r"""['\"]([^'\"]+)['\"]""")
_PREFIX = re.compile(r"""prefix\s*=\s*['\"]([^'\"]+)['\"]""")
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
    r"(BaseModel|(?<!JSON)\.parse\s*\(|\.safeParse\s*\(|z\.object\s*\(|TypeAdapter\s*\(|"
    r"model_validate(?:_json)?\s*\(|parse_obj\s*\(|parse_raw\s*\()"
)
_DEF_HEAD = re.compile(r"(?:async\s+def|def|function)\s+\w+\s*\(")
_UNTRUSTED_EXPR = re.compile(
    r"(user_|user\.|req\.|request\.|"
    r"\b(?:prompt|body|args|input|message|payload|persona)\b(?!\s*:))",
    re.IGNORECASE,
)
_NON_MODEL = {
    "Request",
    "NextRequest",
    "IncomingMessage",
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
_BUSINESS_IO = re.compile(
    r"(\.execute\s*\(|\.query\s*\(|\bfetch\s*\(|"
    r"\brequests\s*\.|\bhttpx\s*\.|\bsupabase\s*\.|\bprisma\s*\.|"
    r"\.insert\s*\(|\.update\s*\(|\.delete\s*\(|\.upsert\s*\(|"
    r"\bstripe\b|\bopenai\b|\bsmtplib\b|\bsubprocess\b|\bos\s*\.\s*system\s*\()",
    re.IGNORECASE,
)
_STATUS_KEYS = {"status", "ok", "success", "error", "message", "detail", "msg"}
_AUTH_LINE = re.compile(r"^(?P<file>.+):(?P<line>\d+):\s(?P<code>.*)$")
_ROUTE_OBJECT = re.compile(
    r"@\s*([A-Za-z_][\w]*(?:\s*\.\s*[A-Za-z_][\w]*)*)\s*\.\s*"
    r"(?:get|post|put|patch|delete|api_route|route|head|options|websocket)\s*\(",
    re.IGNORECASE,
)
_EXPRESS_ROUTE_OBJECT = re.compile(
    r"\b([A-Za-z_][\w]*)\s*\.\s*(?:get|post|put|patch|delete)\s*\(\s*['\"]",
    re.IGNORECASE,
)
_APP_ASSIGN = re.compile(r"\b([A-Za-z_][\w]*)\s*=\s*(?:APIRouter|FastAPI)\s*\(")
_INCLUDE_ROUTER = re.compile(r"\binclude_router\s*\(")
_ROUTER_USE = re.compile(r"\b([A-Za-z_][\w]*)\s*\.\s*use\s*\(")
_AUTHISH_CALLABLE = re.compile(
    r"(?:current_?user|active_?user|get_(?:current_)?(?:active_)?user|"
    r"require_?(?:user|auth)|auth_required|login_required|"
    r"verify_?(?:token|session|jwt)|authenticate|authentication|"
    r"\bauth\b|jwt|oauth|passport|clerk|get_?session|principal)",
    re.IGNORECASE,
)
_DEPENDS_NAME = re.compile(
    r"\b(?:Depends|Security)\s*\(\s*([A-Za-z_][\w.]*)",
    re.IGNORECASE,
)
_ANNOTATED_USER_DEPENDS = re.compile(
    r"Annotated\s*\[\s*(?:[\w.]+\.)?(?:User|CurrentUser|AuthUser|Principal)\b"
    r"[^\]]{0,240}\b(?:Depends|Security)\s*\(",
    re.IGNORECASE,
)
_NAMED_AUTH_PARAM = re.compile(
    r"\b(?:current_user|currentUser|authenticated_user|auth_user)\s*"
    r"(?::\s*[^=\n]{0,160})?=\s*(?:Depends|Security)\s*\(",
    re.IGNORECASE,
)
_TOOL_SIDE_EFFECT = re.compile(
    r"(\.insert\s*\(|\.update\s*\(|\.delete\s*\(|\.upsert\s*\(|"
    r"\b(?:INSERT|UPDATE|DELETE)\b|"
    r"\bstripe\b|payment_?intents?|"
    r"subprocess\.|\bos\s*\.\s*system\s*\(|"
    r"\b(?:execFile(?:Async|Sync)?|execSync|spawn(?:Sync)?)\s*\(|"
    r"requests\.(?:post|put|patch|delete)\s*\(|"
    r"httpx\.(?:post|put|patch|delete)\s*\()",
    re.IGNORECASE,
)
_SENSITIVE_FIELD = re.compile(
    r"^(?:user_id|userId|org_id|orgId|role|is_admin|isAdmin|"
    r"price|amount|total|unit_price|unitPrice|"
    r"(?:price|amount|total|unit_price|unitPrice)(?:_cents|Cents|_usd|Usd))$"
)
_BARE_ROOTS = ("formData", "searchParams", "body", "payload", "data", "params", "query")
_ROOT_ASSIGN = re.compile(
    r"(?:(?:const|let|var)\s+)?\b([A-Za-z_][\w]*)\s*=(?!=)\s*(?P<rhs>[^;\n]+)"
)
_DESTRUCTURE = re.compile(r"\{([^{}]+)\}\s*=(?!=)\s*([^;\n]+)")
_CALL_NAME = re.compile(r"\b([A-Za-z_][\w]*(?:\s*\.\s*[A-Za-z_][\w]*)*)\s*\(")
_NON_SINK_LEAF = {
    "get",
    "keys",
    "values",
    "items",
    "append",
    "extend",
    "pop",
    "join",
    "strip",
    "lower",
    "upper",
    "lstrip",
    "rstrip",
    "replace",
    "split",
    "format",
    "copy",
    "startswith",
    "endswith",
    "isdigit",
    "encode",
    "decode",
    "parse",
    "safeparse",
    "model_validate",
    "model_validate_json",
    "parse_obj",
    "parse_raw",
    "dumps",
    "loads",
    "stringify",
    "len",
    "str",
    "int",
    "float",
    "bool",
    "list",
    "dict",
    "set",
    "tuple",
    "isinstance",
    "type",
    "repr",
    "sorted",
    "enumerate",
    "zip",
    "map",
    "foreach",
    "reduce",
    "any",
    "all",
    "min",
    "max",
    "abs",
    "round",
    "sum",
    "print",
    "info",
    "debug",
    "warning",
    "error",
    "exception",
    "warn",
    "trace",
    "log",
    "depends",
    "security",
    "field",
    "header",
    "cookie",
    "json",
    "trim",
    "tostring",
    "valueof",
    "includes",
    "indexof",
    "validate",
    "validator",
    "sanitize",
    "normalize",
    "normalise",
}
_RESPONSE_HEADS = {
    "nextresponse",
    "jsonresponse",
    "response",
    "htmlresponse",
    "redirectresponse",
    "fileresponse",
    "orjsonresponse",
    "plainresponse",
    "plaintextresponse",
    "httpexception",
    "console",
    "logger",
    "logging",
    "log",
}
_ROLE_SYSTEM = re.compile(
    r"""(['"])role\1\s*:\s*(['"])system\2""",
    re.IGNORECASE,
)
_CONTENT_KEY = re.compile(r"""(['"])content\1\s*:""")
_SYSTEM_CTOR = re.compile(r"\bSystemMessage(?:PromptTemplate)?\s*\(", re.IGNORECASE)
_SYSTEM_TUPLE = re.compile(r"""[([]\s*(['"])system\1\s*,\s*""", re.IGNORECASE)
_SYSTEM_KEY = re.compile(
    r"(?:^|[{,\n])\s*(['\"]?)system\1\s*:\s*",
    re.IGNORECASE,
)
_SYSTEM_FSTRING = re.compile(
    r"system(?:_prompt|_message)?\s*=\s*f['\"][^'\"]*\{|"
    r"system(?:_prompt|_message)?\s*=\s*`[^`]*\$\{"
)
_EXEC_SINKS = (
    re.compile(r"subprocess\.(?:run|call|Popen|check_output|check_call)\s*\(", re.IGNORECASE),
    re.compile(r"os\.system\s*\(", re.IGNORECASE),
    re.compile(r"\beval\s*\("),
    re.compile(r"(?<![\w.])exec\s*\("),
    re.compile(r"(?:fs\.writeFile(?:Sync)?|writeFile(?:Sync)?)\s*\("),
    re.compile(r"\b(?:execFile(?:Async|Sync)?|execSync|spawn(?:Sync)?)\s*\(", re.IGNORECASE),
)
_HTTP_SINK = re.compile(
    r"\b(?:fetch|axios\.(?:post|put|patch|delete)|requests\.(?:post|put|patch|delete)|httpx\.(?:post|put|patch|delete))\s*\(",
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
    if _skips_missing_auth(unit):
        return 0.05
    if not _mutates(unit) or not _is_entrypoint(unit):
        return 0.05
    if _has_local_auth(unit.source) or _auth_context_covers(unit, auth_context):
        return 0.05
    return 0.93


def _skips_missing_auth(unit: CodeUnit) -> bool:
    method = (unit.http_method or "").strip().upper()
    if method == "TOOL":
        return False
    return unit.kind == "function" and not method


def _mutates(unit: CodeUnit) -> bool:
    method = (unit.http_method or "").upper()
    if method == "TOOL":
        return _TOOL_SIDE_EFFECT.search(unit.source) is not None
    if method in _MUTATING_METHODS:
        return True
    return _MUTATING_CALL.search(unit.source) is not None


def _is_entrypoint(unit: CodeUnit) -> bool:
    method = (unit.http_method or "").upper()
    if method == "TOOL" or unit.kind in {"route", "tool"} or unit.route_path:
        return True
    if method in _MUTATING_METHODS | {"GET", "HEAD"}:
        return True
    return bool(_ROUTE_DECORATOR.search(unit.source))


def _has_local_auth(source: str) -> bool:
    if _LOCAL_AUTH.search(source) or _ANNOTATED_USER_DEPENDS.search(source) or _NAMED_AUTH_PARAM.search(source):
        return True
    if _dependencies_are_auth(source):
        return True
    return any(_AUTHISH_CALLABLE.search(match.group(1)) for match in _DEPENDS_NAME.finditer(source))


def _auth_context_covers(unit: CodeUnit, auth_context: str) -> bool:
    if not auth_context.strip():
        return False
    if _object_auth_covers(unit, auth_context):
        return True
    return _path_auth_covers(unit.route_path, auth_context)


def _iter_auth_lines(auth_context: str):
    for raw in auth_context.splitlines():
        stripped = raw.strip()
        if not stripped:
            continue
        match = _AUTH_LINE.match(stripped)
        if match:
            yield match.group("file"), match.group("code")
        else:
            yield None, stripped


def _route_objects(source: str) -> set[str]:
    names = set(_ROUTE_OBJECT.findall(source))
    names.update(_EXPRESS_ROUTE_OBJECT.findall(source))
    return _leaves(names)


def _leaves(names: set[str]) -> set[str]:
    leaves: set[str] = set()
    for name in names:
        parts = [part for part in re.split(r"\s*\.\s*", name) if part]
        if parts:
            leaves.add(parts[-1])
    return leaves


def _object_auth_covers(unit: CodeUnit, auth_context: str) -> bool:
    objects = _route_objects(unit.source)
    if not objects:
        return False
    for file, code in _iter_auth_lines(auth_context):
        if file is not None and file != unit.file:
            continue
        if objects & _authenticated_objects(code, unit.route_path):
            return True
    return False


def _authenticated_objects(code: str, route_path: str | None) -> set[str]:
    found: set[str] = set()
    for match in _APP_ASSIGN.finditer(code):
        call = _balanced(code, match.end() - 1, "(", ")")
        if call and _dependencies_are_auth(call):
            found.add(match.group(1))
    for match in _INCLUDE_ROUTER.finditer(code):
        call = _balanced(code, match.end() - 1, "(", ")")
        if not call or not _dependencies_are_auth(call):
            continue
        name = _first_arg_name(call)
        if name:
            found.add(name)
    for match in _ROUTER_USE.finditer(code):
        call = _balanced(code, match.end() - 1, "(", ")")
        if not call or _AUTHISH_CALLABLE.search(call) is None:
            continue
        if _mount_covers(call, route_path):
            found.add(match.group(1))
    return found


def _first_arg_name(call: str) -> str | None:
    inner = call[1:-1].lstrip()
    match = re.match(r"([A-Za-z_][\w]*)(?:\s*\.\s*([A-Za-z_][\w]*))?", inner)
    if match is None:
        return None
    return match.group(2) or match.group(1)


def _mount_covers(call: str, route_path: str | None) -> bool:
    mounts = [item for item in _QUOTED.findall(call) if item.startswith("/")]
    if not mounts:
        return True
    if not route_path:
        return False
    path = _normalize_path(route_path)
    for mount in mounts:
        norm = _normalize_path(mount)
        if path == norm or path.startswith(norm + "/"):
            return True
        if _path_covered(mount, path):
            return True
    return False


def _dependencies_are_auth(code: str) -> bool:
    match = re.search(r"\bdependencies\s*=\s*\[", code)
    if match is None:
        return False
    bracket = code.find("[", match.start())
    span = _balanced(code, bracket, "[", "]") if bracket >= 0 else None
    inside = span if span is not None else code[match.start() :]
    if re.search(r"\bSecurity\s*\(", inside):
        return True
    return any(_AUTHISH_CALLABLE.search(dep.group(1)) for dep in _DEPENDS_NAME.finditer(inside))


def _path_auth_covers(route_path: str | None, auth_context: str) -> bool:
    if not route_path or not auth_context.strip():
        return False
    path = _normalize_path(route_path)
    for _file, code in _iter_auth_lines(auth_context):
        matcher = re.search(r"\bmatcher\b", code) is not None
        for pattern in _QUOTED.findall(code):
            if pattern in {"*", "/*"}:
                if matcher and _path_covered(pattern, path):
                    return True
                continue
            if pattern.startswith("/") and _path_covered(pattern, path):
                return True
        if _dependencies_are_auth(code):
            for prefix in _PREFIX.findall(code):
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


def _score_idor(unit: CodeUnit) -> float:
    exprs, names = _tainted(unit)
    if not exprs and not names:
        return 0.05
    if _tainted_reaches_sink(unit.source, exprs, names):
        return 0.93
    return 0.05


def _score_prompt_injection(unit: CodeUnit) -> float:
    source = unit.source
    if _system_interpolates_untrusted(source):
        return 0.93
    if _untrusted_sql(source):
        return 0.91
    if _untrusted_exec(source):
        return 0.91
    return 0.05


def _untrusted_sql(source: str) -> bool:
    bound = _untrusted_bound_names(source)
    for match in re.finditer(r"\.execute\s*\(", source, re.IGNORECASE):
        call = _call_from(source, match.start())
        if call and _expression_is_untrusted(_read_expr(call[1:-1], 0), bound):
            return True
    return False


def _system_interpolates_untrusted(source: str) -> bool:
    bound = _untrusted_bound_names(source)
    for match in _SYSTEM_FSTRING.finditer(source):
        literal = _opening_literal(source, match.start())
        if literal and _expression_is_untrusted(literal, bound):
            return True
    seen: set[tuple[int, int]] = set()
    for match in _ROLE_SYSTEM.finditer(source):
        span = _enclosing_object(source, match.start())
        if span is None or span in seen:
            continue
        seen.add(span)
        expr = _content_in_span(source, span)
        if expr and _expression_is_untrusted(expr, bound):
            return True
    for expr in _system_ctor_exprs(source):
        if _expression_is_untrusted(expr, bound):
            return True
    for expr in _system_tuple_exprs(source):
        if _expression_is_untrusted(expr, bound):
            return True
    for expr in _system_key_exprs(source):
        if _expression_is_untrusted(expr, bound):
            return True
    return False


def _untrusted_exec(source: str) -> bool:
    bound = _untrusted_bound_names(source)
    for pattern in _EXEC_SINKS:
        for match in pattern.finditer(source):
            call = _call_from(source, match.start())
            if call and _expression_is_untrusted(call, bound):
                return True
    for match in _HTTP_SINK.finditer(source):
        call = _call_from(source, match.start())
        if call and _expression_is_untrusted(_read_expr(call[1:-1], 0), bound):
            return True
    return False


def _call_from(source: str, start: int) -> str | None:
    paren = source.find("(", start)
    if paren < 0:
        return None
    return _balanced(source, paren, "(", ")")


def _score_mock(unit: CodeUnit) -> float:
    source = unit.source
    if _BUSINESS_IO.search(source):
        return 0.05
    if _FAKE_SUCCESS.search(source):
        return 0.91
    if _unimplemented_body(source):
        return 0.88
    if _STUB_WORD.search(source) and re.search(r"\breturn\b", source):
        return 0.90
    if _returns_hardcoded_record(source):
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
    return bool(_model_param_names(source))


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


def _tainted(unit: CodeUnit) -> tuple[list[str], set[str]]:
    source = unit.source
    roots = set(_BARE_ROOTS)
    if _is_entrypoint(unit):
        roots.update(_model_param_names(source))
    roots.update(_assigned_roots(source))
    reader = _field_reader(roots)
    exprs: list[str] = []
    names: set[str] = set()
    for match in reader.finditer(source):
        field = match.group("attr") or match.group("key") or match.group("get")
        if field and _SENSITIVE_FIELD.fullmatch(field):
            exprs.append(match.group(0))
    for match in _DESTRUCTURE.finditer(source):
        if not _rhs_is_client(match.group(2), roots):
            continue
        for part in match.group(1).split(","):
            piece = part.strip()
            if not piece:
                continue
            if ":" in piece:
                field, alias = (item.strip() for item in piece.split(":", 1))
            else:
                field = alias = piece.split("=")[0].strip()
            if _SENSITIVE_FIELD.fullmatch(field) and re.fullmatch(r"[A-Za-z_][\w]*", alias):
                names.add(alias)
    _propagate_names(source, exprs, names)
    return exprs, names


def _field_reader(roots: set[str]) -> re.Pattern[str]:
    ordered = list(dict.fromkeys([*roots]))
    ordered.sort(key=len, reverse=True)
    bare = "|".join(re.escape(name) for name in ordered)
    compound = r"req(?:uest)?\s*\.\s*(?:body|query_params|query)"
    return re.compile(
        rf"(?P<root>{compound}|(?<!\.)\b(?:{bare})\b)\s*"
        rf"(?:\.\s*(?P<attr>[A-Za-z_][\w]*)"
        rf"|\[\s*['\"](?P<key>[^'\"]+)['\"]\s*\]"
        rf"|\.\s*get\s*\(\s*['\"](?P<get>[^'\"]+)['\"]\s*\))"
    )


def _assigned_roots(source: str) -> set[str]:
    roots: set[str] = set()
    for match in _ROOT_ASSIGN.finditer(source):
        rhs = match.group("rhs")
        if re.search(r"\breq(?:uest)?\s*\.\s*json\s*\(", rhs):
            roots.add(match.group(1))
            continue
        if re.search(
            r"\b[A-Z][\w.]*\s*\.\s*(?:parse|safeParse|model_validate(?:_json)?|parse_obj)\s*\(",
            rhs,
        ):
            roots.add(match.group(1))
    return roots


def _rhs_is_client(rhs: str, roots: set[str]) -> bool:
    if re.search(r"\breq(?:uest)?\s*\.\s*json\s*\(", rhs):
        return True
    if re.search(r"\breq(?:uest)?\s*\.\s*(?:body|query|query_params)\b", rhs):
        return True
    if re.search(r"\b[A-Z][\w.]*\s*\.\s*(?:parse|safeParse|model_validate(?:_json)?)\s*\(", rhs):
        return True
    return any(re.search(rf"(?<!\.)\b{re.escape(root)}\b", rhs) for root in roots)


def _propagate_names(source: str, exprs: list[str], names: set[str]) -> None:
    assignments = list(
        re.finditer(
            r"(?:(?:const|let|var)\s+)?(?<![!=<>])\b([A-Za-z_][\w]*)\s*=(?!=)\s*([^;\n]+)",
            source,
        )
    )
    for _ in range(3):
        added = False
        for match in assignments:
            lhs = match.group(1)
            if lhs in names or lhs in {"if", "for", "while", "return", "await"}:
                continue
            if _text_has_taint(match.group(2), exprs, names):
                names.add(lhs)
                added = True
        if not added:
            return


def _tainted_reaches_sink(source: str, exprs: list[str], names: set[str]) -> bool:
    for callee, args in _iter_calls(source):
        if _call_is_sink(callee) and _text_has_taint(args, exprs, names):
            return True
    return False


def _iter_calls(source: str):
    for match in _CALL_NAME.finditer(source):
        prefix = source[max(0, match.start() - 16) : match.start()]
        if re.search(r"\b(?:def|class|function)\s*$", prefix):
            continue
        paren = match.end() - 1
        call = _balanced(source, paren, "(", ")")
        if call is None:
            continue
        callee = re.sub(r"\s+", "", match.group(1))
        yield callee, call[1:-1]


def _call_is_sink(callee: str) -> bool:
    parts = [part for part in re.split(r"\.", callee) if part]
    if not parts:
        return False
    head = parts[0]
    leaf = parts[-1]
    if head.lower() in _RESPONSE_HEADS:
        return False
    if leaf.lower() in _NON_SINK_LEAF:
        return False
    if leaf[:1].isupper():
        return re.search(r"(charge|payment|stripe|refund|payout)", leaf, re.IGNORECASE) is not None
    return True


def _text_has_taint(text: str, exprs: list[str], names: set[str]) -> bool:
    if any(expr and expr in text for expr in exprs):
        return True
    return any(re.search(rf"\b{re.escape(name)}\b", text) for name in names)


def _model_param_names(source: str) -> set[str]:
    signature = _first_signature(source)
    if not signature:
        return set()
    names: set[str] = set()
    for param in _split_top(signature, ","):
        if re.search(r"\b(?:Depends|Security)\s*\(", param):
            continue
        match = re.match(r"\s*\**([A-Za-z_][\w]*)\s*:\s*([A-Za-z_][\w]*)\b", param)
        if match is None:
            continue
        pname, ann = match.group(1), match.group(2)
        if ann[:1].isupper() and ann not in _NON_MODEL:
            names.add(pname)
    return names


def _expression_is_untrusted(expr: str, bound: set[str] | None = None) -> bool:
    code = _code_outside_literals(expr)
    if _UNTRUSTED_EXPR.search(code):
        return True
    if not bound:
        return False
    return any(token in bound for token in re.findall(r"[A-Za-z_][\w]*", code))


def _untrusted_bound_names(source: str) -> set[str]:
    assignments = list(
        re.finditer(
            r"(?:(?:const|let|var)\s+)?(?<![!=<>])\b([A-Za-z_][\w]*)\s*=(?!=)\s*([^;\n]+)",
            source,
        )
    )
    names: set[str] = set()
    for _ in range(3):
        added = False
        for match in assignments:
            lhs = match.group(1)
            if lhs in names:
                continue
            if _expression_is_untrusted(match.group(2), names):
                names.add(lhs)
                added = True
        if not added:
            break
    return names


def _code_outside_literals(text: str) -> str:
    parts: list[str] = []
    index = 0
    while index < len(text):
        if _starts_literal(text, index):
            end, interps = _consume_literal(text, index)
            if interps:
                parts.append(" " + " ".join(interps) + " ")
            if end <= index:
                end = index + 1
            index = end
            continue
        parts.append(text[index])
        index += 1
    return "".join(parts)


def _starts_literal(text: str, index: int) -> bool:
    char = text[index]
    if char in {"'", '"', "`"}:
        return True
    if char not in {"f", "F", "r", "R", "b", "B", "u", "U"}:
        return False
    cursor = index
    flags = 0
    while cursor < len(text) and text[cursor] in {"f", "F", "r", "R", "b", "B", "u", "U"} and flags < 3:
        cursor += 1
        flags += 1
    return cursor < len(text) and text[cursor] in {"'", '"'}


def _opening_literal(source: str, start: int) -> str | None:
    index = start
    while index < len(source) and source[index] not in {"'", '"', "`"}:
        index += 1
    if index >= len(source):
        return None
    begin = index
    cursor = index - 1
    flags = 0
    while cursor >= start and source[cursor] in {"f", "F", "r", "R", "b", "B", "u", "U"} and flags < 3:
        begin = cursor
        flags += 1
        cursor -= 1
    end, _interps = _consume_literal(source, begin)
    if end <= begin:
        return None
    return source[begin:end]


def _consume_literal(text: str, index: int) -> tuple[int, list[str]]:
    interps: list[str] = []
    is_f = False
    cursor = index
    if text[cursor] in {"f", "F", "r", "R", "b", "B", "u", "U"}:
        flags: list[str] = []
        while cursor < len(text) and text[cursor] in {"f", "F", "r", "R", "b", "B", "u", "U"} and len(flags) < 3:
            flags.append(text[cursor].lower())
            cursor += 1
        if cursor < len(text) and text[cursor] in {"'", '"'}:
            is_f = "f" in flags
            index = cursor
        else:
            return index + 1, []
    if index >= len(text) or text[index] not in {"'", '"', "`"}:
        return min(index + 1, len(text)), []
    quote = text[index]
    triple = quote != "`" and text.startswith(quote * 3, index)
    token = quote * 3 if triple else quote
    cursor = index + len(token)
    while cursor < len(text):
        if text.startswith(token, cursor):
            return cursor + len(token), interps
        if quote == "`" and text.startswith("${", cursor):
            expr, cursor = _read_braced(text, cursor + 1)
            interps.append(expr)
            continue
        if is_f and not triple and text[cursor] == "{":
            if cursor + 1 < len(text) and text[cursor + 1] == "{":
                cursor += 2
                continue
            expr, cursor = _read_braced(text, cursor)
            interps.append(expr)
            continue
        if text[cursor] == "\\" and not triple:
            cursor += 2
            continue
        cursor += 1
    return len(text), interps


def _read_braced(text: str, open_index: int) -> tuple[str, int]:
    span = _balanced(text, open_index, "{", "}")
    if span is None:
        return "", min(open_index + 1, len(text))
    return span[1:-1], open_index + len(span)


def _content_in_span(source: str, span: tuple[int, int]) -> str | None:
    segment = source[span[0] : span[1]]
    content = _CONTENT_KEY.search(segment)
    if content is None:
        return None
    return _read_expr(segment, content.end())


def _enclosing_object(source: str, index: int) -> tuple[int, int] | None:
    stack: list[int] = []
    cursor = 0
    while cursor < len(source) and cursor <= index:
        if _starts_literal(source, cursor):
            end, _interps = _consume_literal(source, cursor)
            cursor = end if end > cursor else cursor + 1
            continue
        char = source[cursor]
        if char == "{":
            stack.append(cursor)
        elif char == "}" and stack:
            stack.pop()
        cursor += 1
    if not stack:
        return None
    open_at = stack[-1]
    span = _balanced(source, open_at, "{", "}")
    if span is None:
        return None
    return open_at, open_at + len(span)


def _system_ctor_exprs(source: str) -> list[str]:
    found: list[str] = []
    for match in _SYSTEM_CTOR.finditer(source):
        call = _balanced(source, match.end() - 1, "(", ")")
        if call is None:
            continue
        inner = call[1:-1]
        keyword = re.search(r"\bcontent\s*=\s*", inner)
        found.append(_read_expr(inner, keyword.end() if keyword else 0))
    return found


def _system_tuple_exprs(source: str) -> list[str]:
    return [_read_expr(source, match.end()) for match in _SYSTEM_TUPLE.finditer(source)]


def _system_key_exprs(source: str) -> list[str]:
    found: list[str] = []
    for match in _SYSTEM_KEY.finditer(source):
        if _inside_literal(source, match.start()):
            continue
        found.append(_read_expr(source, match.end()))
    return found


def _inside_literal(source: str, index: int) -> bool:
    cursor = 0
    while cursor < index:
        if _starts_literal(source, cursor):
            end, _interps = _consume_literal(source, cursor)
            if end > index:
                return True
            cursor = end if end > cursor else cursor + 1
            continue
        cursor += 1
    return False


def _read_expr(source: str, start: int) -> str:
    index = start
    length = len(source)
    while index < length and source[index] in " \t\r\n":
        index += 1
    expr_start = index
    depth = 0
    while index < length:
        if _starts_literal(source, index):
            end, _interps = _consume_literal(source, index)
            index = end if end > index else index + 1
            continue
        char = source[index]
        if char in "([{":
            depth += 1
        elif char in ")]}":
            if depth == 0:
                break
            depth -= 1
        elif char == "," and depth == 0:
            break
        elif char == "\n" and depth == 0:
            break
        index += 1
    return source[expr_start:index]


def _unimplemented_body(source: str) -> bool:
    body = _code_lines(source)
    if not body:
        return False
    only = [line for line in body if line not in {"pass", "...", "Ellipsis"}]
    if not only:
        return True
    return len(only) == 1 and re.match(r"raise\s+NotImplementedError\b", only[0]) is not None


def _code_lines(source: str) -> list[str]:
    lines: list[str] = []
    started = False
    for raw in source.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith(("#", "//", "*", "/*", "*/", "'", '"')):
            continue
        if stripped.startswith("@"):
            continue
        if not started:
            if re.match(r"(?:export\s+)?(?:async\s+)?(?:def|function)\b", stripped) or stripped.endswith("{"):
                started = True
            continue
        if stripped in {"{", "}"}:
            continue
        lines.append(stripped)
    return lines


def _returns_hardcoded_record(source: str) -> bool:
    for match in re.finditer(r"\breturn\b", source):
        expr = _read_expr(source, match.end()).strip()
        record = _static_record(_response_payload(expr).strip())
        if record is None:
            continue
        keys, has_number = record
        if has_number and len(keys) >= 2 and not keys <= _STATUS_KEYS:
            return True
    return False


def _response_payload(expr: str) -> str:
    match = re.match(
        r"(?:await\s+)?(?:NextResponse\s*\.\s*json|JSONResponse|Response\s*\.\s*json|jsonify)\s*\(",
        expr,
        re.IGNORECASE,
    )
    if match is None:
        return expr
    call = _balanced(expr, match.end() - 1, "(", ")")
    if call is None:
        return expr
    return _read_expr(call[1:-1], 0)


def _static_record(expr: str) -> tuple[set[str], bool] | None:
    text = expr.strip()
    if len(text) >= 2 and text[0] == "(" and text[-1] == ")":
        inner = _balanced(text, 0, "(", ")")
        if inner == text:
            return _static_record(text[1:-1].strip())
    if text.startswith("{") and _balanced(text, 0, "{", "}") == text:
        return _static_object(text)
    if text.startswith("[") and _balanced(text, 0, "[", "]") == text:
        return _static_list(text)
    return None


def _static_object(text: str) -> tuple[set[str], bool] | None:
    inner = text[1:-1].strip()
    if not inner:
        return set(), False
    keys: set[str] = set()
    has_number = False
    for entry in _split_top(inner, ","):
        entry = entry.strip()
        if not entry:
            continue
        key, value = _split_key_value(entry)
        if key is None or value is None or not _is_literal_key(key):
            return None
        keys.add(_key_name(key))
        literal = _literal_has_number(value.strip())
        if literal is None:
            return None
        has_number = has_number or literal
    return keys, has_number


def _static_list(text: str) -> tuple[set[str], bool] | None:
    inner = text[1:-1].strip()
    if not inner:
        return None
    keys: set[str] = set()
    has_number = False
    for item in _split_top(inner, ","):
        item = item.strip()
        if not item:
            continue
        parsed = _static_record(item)
        if parsed is None:
            return None
        keys |= parsed[0]
        has_number = has_number or parsed[1]
    if not keys:
        return None
    return keys, has_number


def _split_key_value(entry: str) -> tuple[str | None, str | None]:
    parts = _split_top(entry, ":")
    if len(parts) < 2:
        return None, None
    return parts[0].strip(), ":".join(parts[1:]).strip()


def _is_literal_key(key: str) -> bool:
    if re.fullmatch(r"[A-Za-z_][\w]*", key):
        return True
    return len(key) >= 2 and key[0] == key[-1] and key[0] in {"'", '"'}


def _key_name(key: str) -> str:
    if len(key) >= 2 and key[0] == key[-1] and key[0] in {"'", '"'}:
        return key[1:-1]
    return key


def _literal_has_number(value: str) -> bool | None:
    if re.fullmatch(r"-?\d+(?:\.\d+)?", value):
        return True
    if re.fullmatch(r"(?i)true|false|null|none", value):
        return False
    if _is_plain_string(value):
        return False
    if value[:1] in {"{", "["}:
        nested = _static_record(value)
        if nested is None:
            return None
        return nested[1]
    return None


def _is_plain_string(value: str) -> bool:
    if not value or value[0] in {"f", "F"}:
        return False
    if len(value) < 2 or value[0] not in {"'", '"', "`"} or value[-1] != value[0]:
        return False
    return not (value[0] == "`" and "${" in value)


def _split_top(text: str, sep: str) -> list[str]:
    parts: list[str] = []
    start = 0
    depth = 0
    index = 0
    while index < len(text):
        if _starts_literal(text, index):
            end, _interps = _consume_literal(text, index)
            index = end if end > index else index + 1
            continue
        char = text[index]
        if char in "([{":
            depth += 1
        elif char in ")]}" and depth:
            depth -= 1
        elif char == sep and depth == 0:
            parts.append(text[start:index])
            start = index + 1
        index += 1
    parts.append(text[start:])
    return parts


def _balanced(text: str, open_index: int, open_ch: str, close_ch: str) -> str | None:
    if open_index < 0 or open_index >= len(text) or text[open_index] != open_ch:
        return None
    depth = 0
    index = open_index
    while index < len(text):
        if _starts_literal(text, index):
            end, _interps = _consume_literal(text, index)
            index = end if end > index else index + 1
            continue
        char = text[index]
        if char == open_ch:
            depth += 1
        elif char == close_ch:
            depth -= 1
            if depth == 0:
                return text[open_index : index + 1]
        index += 1
    return None


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
