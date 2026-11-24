"""Offline Layer 2 scores. Generic code semantics, no network.

Prefers missing a bug over a false alarm. ``OFFLINE_HEURISTIC_VERSION`` is part
of the offline cache key, so a heuristic change cannot reuse stale scores.
"""

from __future__ import annotations

import re
from collections.abc import Callable

from vibecleaner.cache import OFFLINE_MODEL, ChunkVerdict
from vibecleaner.models import CodeUnit
from vibecleaner.deterministic import _name_parts as _word_parts

OFFLINE_HEURISTIC_VERSION = "4"

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
_STAR_PROJECTION = re.compile(r"""\.select\(\s*['\"]?\*['\"]?\s*\)""")
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
    r"(user_|user\.|"
    r"req(?:uest)?\s*\.\s*(?:body|query|params|form|json|args|data|values)\b|"
    r"req\.|request\.|"
    r"\b(?:prompt|body|input|message|payload|persona|\w*instructions)\b(?!\s*:)|"
    r"\.function\s*\.\s*arguments\b|"
    r"\btool_calls?\b|"
    r"\[\s*['\"]arguments['\"]\s*\])",
    re.IGNORECASE,
)
_UNAUTH_REJECTION = re.compile(
    r"\bHTTPException\s*\(\s*40[13]\b"
    r"|\bHTTPException\s*\([^)]{0,300}\bstatus_code\s*=\s*40[13]\b"
    r"|status(?:_code)?\s*[:=]\s*40[13]\b"
    r"|\.status\s*\(\s*40[13]\s*\)"
    r"|\babort\s*\(\s*40[13]\s*\)"
    r"|\braise\s+PermissionError\b",
    re.IGNORECASE,
)
_AUTH_PARTS = frozenset(
    {
        "auth",
        "authenticated",
        "authorize",
        "authorized",
        "user",
        "current",
        "session",
        "token",
        "jwt",
        "login",
        "signed",
        "principal",
        "identity",
        "account",
        "member",
        "staff",
        "admin",
        "tenant",
        "operator",
        "role",
        "permission",
        "permissions",
        "scope",
        "scopes",
        "api",
        "key",
        "apikey",
        "verify",
        "require",
        "required",
        "guard",
        "gate",
        "gatekeeper",
        "protect",
        "protected",
        "ensure",
        "assert",
        "clerk",
        "oauth",
        "bearer",
        "credential",
        "credentials",
        "pin",
        "owner",
    }
)
_AUTH_EXTRA = frozenset(
    {
        "authentication",
        "authenticate",
        "authenticating",
        "authorization",
        "authorizing",
    }
)
_RESOURCE_PARTS = frozenset(
    {
        "db",
        "database",
        "settings",
        "config",
        "redis",
        "cache",
        "pagination",
        "paginate",
        "page",
        "limit",
        "logger",
        "client",
        "http",
    }
)
_SESSION_PROVIDER_PARTS = frozenset(
    {
        "get",
        "async",
        "db",
        "database",
        "session",
        "factory",
        "maker",
        "local",
        "scoped",
    }
)
_GETTER_FILLER = frozenset({"get", "async"})
_CREDENTIAL_PARTS = frozenset(
    {
        "header",
        "headers",
        "cookie",
        "cookies",
        "token",
        "session",
        "user",
        "auth",
        "authenticated",
        "authorize",
        "authorized",
        "authentication",
        "authorization",
        "jwt",
        "login",
        "signed",
        "signature",
        "principal",
        "identity",
        "credential",
        "credentials",
        "bearer",
        "oauth",
        "clerk",
        "apikey",
        "pin",
        "password",
        "secret",
        "operator",
        "member",
        "staff",
        "admin",
        "tenant",
        "account",
        "owner",
        "role",
    }
)
_CREDENTIAL_CALL = re.compile(
    r"\b(?:verify|require|ensure|assert|guard|protect|authenticate)[A-Za-z0-9_]*\s*\(",
    re.IGNORECASE,
)
_IF_HEAD = re.compile(r"\b(?:elif|else\s+if|if)\b")
_CONDITION_CONTINUES = re.compile(r"(?:and|or|&&|\|\|)\b")
_AUTH_WRAPPER = re.compile(r"\b(with[A-Z_][\w]*)\s*\(")
_CONTROL_WORDS = frozenset(
    {
        "if",
        "elif",
        "else",
        "for",
        "while",
        "switch",
        "catch",
        "return",
        "try",
        "except",
        "finally",
        "with",
        "raise",
        "throw",
        "new",
        "await",
        "typeof",
        "instanceof",
        "delete",
        "void",
        "case",
        "do",
        "function",
        "class",
        "yield",
        "assert",
    }
)
_TARGET_METHODS = frozenset(
    {
        "strip",
        "str",
        "encode",
        "decode",
        "format",
        "join",
        "trim",
        "tostring",
        "string",
        "lower",
        "upper",
    }
)
_SKIP_PARAM_NAMES = frozenset({"self", "cls", "args", "kwargs", "argv"})
_ALLOWLIST_WORD = r"(?:allow(?:ed|list|_list)?|whitelist|permit(?:ted)?|trusted|approved)"
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
    r"\b([A-Za-z_][\w]*)\s*\.\s*(?:get|post|put|patch|delete|all)\s*\(\s*['\"]",
    re.IGNORECASE,
)
_APP_ASSIGN = re.compile(r"\b([A-Za-z_][\w]*)\s*=\s*(?:APIRouter|FastAPI)\s*\(")
_INCLUDE_ROUTER = re.compile(r"\binclude_router\s*\(")
_ROUTER_USE = re.compile(r"\b([A-Za-z_][\w]*)\s*\.\s*use\s*\(")
_ADD_MIDDLEWARE = re.compile(r"\b([A-Za-z_][\w]*)\s*\.\s*add_middleware\s*\(")
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

class OfflineHeuristicBackend:
    """Deterministic zero-network fallback. Prefers missing a bug over a false alarm."""

    name = OFFLINE_MODEL

    def __init__(self) -> None:
        self._catalog: tuple[CodeUnit, ...] = ()

    def bind_catalog(self, units: list[CodeUnit]) -> None:
        """Remember every unit in the scan so a caller can be scored via its callee."""
        self._catalog = tuple(units)

    async def judge_chunk(self, auth_context: str, units: list[CodeUnit]) -> ChunkVerdict:
        scores: dict[str, dict[str, float]] = {}
        severity: dict[str, float] = {}
        for unit in units:
            unit_scores = {
                "D3.missing_auth": _score_missing_auth(unit, auth_context),
                "D4.idor_or_price_trust": _score_idor(unit),
                "D5.prompt_injection": _score_prompt_injection(unit, self._catalog),
                "D6b.hardcoded_mock_stub": _score_mock(unit),
                "D7a.n_plus_one_loop": _score_n_plus_one(unit),
                "D7b.missing_boundary_schema": _score_boundary(unit),
            }
            scores[unit.unit_id] = unit_scores
            severity[unit.unit_id] = module_risk_from_scores(unit_scores)
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


_HTTP_CLIENT_OBJECTS = frozenset({"axios", "requests", "httpx"})


def _has_local_auth(source: str) -> bool:
    code = _auth_code(source)
    if _LOCAL_AUTH.search(code) or _ANNOTATED_USER_DEPENDS.search(code) or _NAMED_AUTH_PARAM.search(code):
        return True
    if _rejects_unauthenticated(code):
        return True
    if _has_auth_wrapper(code):
        return True
    if _route_middleware_has_auth(source):
        return True
    if _dependencies_are_auth(code):
        return True
    return _span_has_auth_dependency(code)


def _route_middleware_has_auth(source: str) -> bool:
    stripped = _strip_comments(source)
    for match in _EXPRESS_ROUTE_OBJECT.finditer(stripped):
        if match.group(1).lower() in _HTTP_CLIENT_OBJECTS:
            continue
        if re.search(r"\b(?:await|return)\s+$", stripped[: match.start()]):
            continue
        call = _call_from(stripped, match.start())
        if call is None:
            continue
        args = _split_top(call[1:-1], ",")
        if len(args) < 3:
            continue
        path_arg = args[0].strip()
        if len(path_arg) < 2 or path_arg[0] not in {"'", '"', "`"}:
            continue
        if not path_arg[1:].startswith(("/", "*")):
            continue
        last = args[-1].strip()
        if not last or last.startswith(("{", "[")):
            continue
        for raw in args[1:-1]:
            mid = raw.strip()
            ident = re.match(r"^([A-Za-z_][\w]*(?:\s*\.\s*[A-Za-z_][\w]*)*)(.*)$", mid, re.DOTALL)
            if ident is None:
                continue
            name, rest = ident.group(1), ident.group(2).strip()
            if rest and not (rest.startswith("(") and _balanced(rest, 0, "(", ")") == rest):
                continue
            if _looks_like_auth_name(name):
                return True
    return False


def _auth_context_covers(unit: CodeUnit, auth_context: str) -> bool:
    if not auth_context.strip():
        return False
    if _object_auth_covers(unit, auth_context):
        return True
    if _path_auth_covers(unit.route_path, auth_context):
        return True
    return _unnamed_app_auth(unit, auth_context)


def _unnamed_app_auth(unit: CodeUnit, auth_context: str) -> bool:
    """Cover routes when the auth line is ``FastAPI(dependencies=[...])`` with the name dropped."""
    if not _route_objects(unit.source):
        return False
    for file, code in _iter_auth_lines(auth_context):
        if file is not None and file != unit.file:
            continue
        if _APP_ASSIGN.search(code):
            continue
        if re.search(r"\bFastAPI\s*\(", code) and _dependencies_are_auth(code):
            return True
    return False


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
        if call and _call_has_auth_callable(call) and _mount_covers(call, route_path):
            found.add(match.group(1))
    for match in _ADD_MIDDLEWARE.finditer(code):
        call = _balanced(code, match.end() - 1, "(", ")")
        if call and _call_has_auth_callable(call):
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




def _dependency_leaf(name: str) -> str:
    parts = [part for part in re.split(r"\s*\.\s*", name) if part]
    return parts[-1] if parts else name




def _part_is_auth(part: str) -> bool:
    if part in _AUTH_PARTS or part in _AUTH_EXTRA:
        return True
    singular = part[:-1] if part.endswith("s") else ""
    return singular in _AUTH_PARTS or singular in _AUTH_EXTRA


def _is_resource_name(parts: tuple[str, ...]) -> bool:
    if not parts:
        return False
    if "session" in parts and set(parts) <= _SESSION_PROVIDER_PARTS:
        return True
    meaningful = [part for part in parts if part not in _GETTER_FILLER and not part.isdigit()]
    return bool(meaningful) and all(part in _RESOURCE_PARTS for part in meaningful)


def _looks_like_auth_name(name: str) -> bool:
    parts = _word_parts(_dependency_leaf(name))
    if not parts or _is_resource_name(parts):
        return False
    return any(_part_is_auth(part) for part in parts)


def _span_has_auth_dependency(code: str) -> bool:
    code = _auth_code(code)
    if re.search(r"\bSecurity\s*\(", code):
        return True
    return any(_looks_like_auth_name(match.group(1)) for match in _DEPENDS_NAME.finditer(code))


def _dependencies_are_auth(code: str) -> bool:
    code = _auth_code(code)
    match = re.search(r"\bdependencies\s*=\s*\[", code)
    if match is None:
        return False
    bracket = code.find("[", match.start())
    span = _balanced(code, bracket, "[", "]") if bracket >= 0 else None
    inside = span if span is not None else code[match.start() :]
    return _span_has_auth_dependency(inside)


def _call_has_auth_callable(call: str) -> bool:
    code = _auth_code(call)
    return any(_looks_like_auth_name(name) for name in re.findall(r"[A-Za-z_][\w]*", code))


def _has_auth_wrapper(code: str) -> bool:
    source = _auth_code(code)
    return any(_looks_like_auth_name(match.group(1)) for match in _AUTH_WRAPPER.finditer(source))


def _rejects_unauthenticated(source: str) -> bool:
    return _credential_branch_rejects(_auth_code(source))


def _credential_branch_rejects(code: str) -> bool:
    for match in _IF_HEAD.finditer(code):
        parsed = _split_conditional(code, match.end())
        if parsed is None:
            continue
        condition, body = parsed
        if _condition_checks_credential(condition) and _UNAUTH_REJECTION.search(body):
            return True
    return False


def _condition_checks_credential(condition: str) -> bool:
    if _CREDENTIAL_CALL.search(condition):
        return True
    for name in re.findall(r"[A-Za-z_][\w]*", condition):
        parts = set(_word_parts(name))
        if parts & _CREDENTIAL_PARTS:
            return True
        if "api" in parts and "key" in parts:
            return True
    return False


def _split_conditional(code: str, index: int) -> tuple[str, str] | None:
    start = _skip_ws(code, index)
    if start >= len(code):
        return None
    kind, cond_end, body_at = _scan_condition(code, start)
    if kind is None or cond_end is None or body_at is None:
        return None
    condition = _unwrap_condition(code[start:cond_end])
    if kind == "python":
        body, _end = _python_suite(code, body_at)
        return condition, body
    if kind == "brace":
        body, end = _brace_body(code, body_at)
        if body is None:
            return None
        extra, _else_end = _else_clause(code, end)
        return condition, body + extra
    statement, _end = _statement_at(code, body_at)
    return condition, statement


def _scan_condition(code: str, start: int) -> tuple[str | None, int | None, int | None]:
    depth = 0
    cursor = start
    length = len(code)
    opened_paren = code[start] == "("
    while cursor < length:
        char = code[cursor]
        if char == "{" and depth == 0:
            return "brace", cursor, cursor
        if char in "([{":
            depth += 1
            cursor += 1
            continue
        if char in ")]}":
            if depth == 0:
                return None, None, None
            depth -= 1
            cursor += 1
            if depth == 0 and opened_paren and char == ")":
                nxt = _skip_ws(code, cursor)
                if nxt < length and code[nxt] == ":":
                    return "python", cursor, nxt + 1
                if nxt < length and code[nxt] == "{":
                    return "brace", cursor, nxt
                if nxt < length and _CONDITION_CONTINUES.match(code[nxt:]):
                    continue
                if nxt < length:
                    return "statement", cursor, nxt
                return None, None, None
            continue
        if depth == 0 and char == ":":
            return "python", cursor, cursor + 1
        if depth == 0 and char == "\n":
            return None, None, None
        cursor += 1
    return None, None, None


def _unwrap_condition(condition: str) -> str:
    text = condition.strip()
    if len(text) >= 2 and text[0] == "(" and text[-1] == ")" and _balanced(text, 0, "(", ")") == text:
        return text[1:-1].strip()
    return text


def _python_suite(code: str, after_colon: int) -> tuple[str, int]:
    newline = code.find("\n", after_colon)
    if newline < 0:
        return code[after_colon:], len(code)
    base = _indent_at(code, after_colon)
    chunks = [code[after_colon:newline]]
    cursor = newline + 1
    while cursor < len(code):
        next_nl = code.find("\n", cursor)
        if next_nl < 0:
            next_nl = len(code)
        line = code[cursor:next_nl]
        if line.strip() and _leading_indent(line) <= base:
            break
        chunks.append(line)
        if next_nl >= len(code):
            cursor = len(code)
            break
        cursor = next_nl + 1
    body = "\n".join(chunks)
    extra, end = _else_clause(code, cursor)
    if extra:
        return body + "\n" + extra, end
    return body, cursor


def _else_clause(code: str, index: int) -> tuple[str, int]:
    cursor = _skip_ws(code, index)
    if not re.match(r"else\b", code[cursor:]):
        return "", index
    if re.match(r"else\s+if\b", code[cursor:]):
        return "", index
    after_kw = cursor + len("else")
    after_kw = _skip_ws(code, after_kw)
    if after_kw < len(code) and code[after_kw] == ":":
        return _python_suite(code, after_kw + 1)
    if after_kw < len(code) and code[after_kw] == "{":
        body, end = _brace_body(code, after_kw)
        return body or "", end
    return _statement_at(code, after_kw)


def _brace_body(code: str, open_index: int) -> tuple[str | None, int]:
    span = _balanced(code, open_index, "{", "}")
    if span is None:
        return None, open_index
    return span[1:-1], open_index + len(span)


def _statement_at(code: str, index: int) -> tuple[str, int]:
    cursor = _skip_ws(code, index)
    if cursor >= len(code):
        return "", cursor
    if code[cursor] == "{":
        body, end = _brace_body(code, cursor)
        return body or "", end
    end = cursor
    while end < len(code) and code[end] not in ";\n":
        end += 1
    if end < len(code) and code[end] == ";":
        end += 1
    return code[cursor:end], end


def _skip_ws(code: str, index: int) -> int:
    while index < len(code) and code[index] in " \t\r\n":
        index += 1
    return index


def _indent_at(code: str, pos: int) -> int:
    line_start = code.rfind("\n", 0, pos) + 1
    return _leading_indent(code[line_start:pos])


def _leading_indent(line: str) -> int:
    return len(line) - len(line.lstrip(" \t"))


def _auth_code(text: str) -> str:
    return _strip_comments(_code_outside_literals(text))


def _strip_comments(text: str) -> str:
    def blanks(match: re.Match[str]) -> str:
        return re.sub(r"[^\n]", " ", match.group(0))

    text = re.sub(r"/\*.*?\*/", blanks, text, flags=re.DOTALL)
    return re.sub(r"(?m)#.*$|//.*$", "", text)


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
        for match in _ROUTER_USE.finditer(code):
            call = _balanced(code, match.end() - 1, "(", ")")
            if (
                call
                and _call_has_auth_callable(call)
                and any(item.startswith("/") for item in _QUOTED.findall(call))
                and _mount_covers(call, route_path)
            ):
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


def _score_prompt_injection(unit: CodeUnit, catalog: tuple[CodeUnit, ...] = ()) -> float:
    source = unit.source
    seeds = _tool_param_names(unit)
    if _system_interpolates_untrusted(source, seeds):
        return 0.93
    if _untrusted_sql(source, seeds):
        return 0.91
    if _untrusted_exec(source, seeds):
        return 0.91
    if _calls_dangerous_helper(unit, catalog, seeds):
        return 0.91
    return 0.05


def _untrusted_sql(source: str, seeds: set[str] | None = None) -> bool:
    bound = _untrusted_bound_names(source, seeds)
    for match in re.finditer(r"\.execute\s*\(", source, re.IGNORECASE):
        call = _call_from(source, match.start())
        if call and _expression_is_untrusted(_read_expr(call[1:-1], 0), bound):
            return True
    return False


def _system_interpolates_untrusted(source: str, seeds: set[str] | None = None) -> bool:
    bound = _untrusted_bound_names(source, seeds)
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


def _untrusted_exec(source: str, seeds: set[str] | None = None) -> bool:
    bound = _untrusted_bound_names(source, seeds)
    for pattern in _EXEC_SINKS:
        for match in pattern.finditer(source):
            call = _call_from(source, match.start())
            if call and _expression_is_untrusted(call, bound) and not _target_allowlisted(source, call):
                return True
    for match in _HTTP_SINK.finditer(source):
        call = _call_from(source, match.start())
        if not call:
            continue
        target = _read_expr(call[1:-1], 0)
        if _expression_is_untrusted(target, bound) and not _target_allowlisted(source, target):
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
    if _UNBOUNDED_SQL.search(source) or _STAR_PROJECTION.search(source):
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
        call = _call_from(source, match.start())
        window = call if call is not None else source[match.start() : match.start() + 500]
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
    if _USES_FIELDS.search(source) or _raw_payload_reaches_io(source):
        return 0.90
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


_ASSIGNMENT = re.compile(
    r"(?:(?:const|let|var)\s+)?(?<![!=<>])\b([A-Za-z_][\w]*)\s*=(?!=)\s*([^;\n]+)"
)
_NOT_A_NAME = frozenset({"if", "for", "while", "return", "await"})


def _absorb_assignments(
    source: str,
    names: set[str],
    rhs_is_tainted: Callable[[str, set[str]], bool],
    skip: frozenset[str] = frozenset(),
) -> None:
    assignments = list(_ASSIGNMENT.finditer(source))
    for _ in range(3):
        added = False
        for match in assignments:
            lhs = match.group(1)
            if lhs in names or lhs in skip:
                continue
            rhs = match.group(2)
            if rhs.strip().startswith("("):
                paren_idx = source.find("(", match.start(2))
                if paren_idx >= 0:
                    span = _balanced(source, paren_idx, "(", ")")
                    if span is not None:
                        rhs = span
            if rhs_is_tainted(rhs, names):
                names.add(lhs)
                added = True
        if not added:
            return


def _propagate_names(source: str, exprs: list[str], names: set[str]) -> None:
    _absorb_assignments(
        source,
        names,
        lambda rhs, bound: _text_has_taint(rhs, exprs, bound),
        _NOT_A_NAME,
    )


def _tainted_reaches_sink(source: str, exprs: list[str], names: set[str]) -> bool:
    for callee, args in _iter_calls(source):
        if not _call_is_sink(callee) or _is_identity_rejection(args):
            continue
        if _text_has_taint(args, exprs, names):
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
    if head.lower() in _CONTROL_WORDS or leaf.lower() in _CONTROL_WORDS:
        return False
    if head.lower() in _RESPONSE_HEADS:
        return False
    if leaf.lower() in _NON_SINK_LEAF:
        return False
    if leaf[:1].isupper():
        return re.search(r"(charge|payment|stripe|refund|payout)", leaf, re.IGNORECASE) is not None
    return True


_SESSION_IDENTITY = re.compile(
    r"\b(?:session|principal)\b|\b(?:req|request)\s*\.\s*(?:user|state)\b|\buser\s*\.\s*id\b",
    re.IGNORECASE,
)
_COMPARISON = re.compile(r"(?:!==|!=|===|==)")


def _is_identity_rejection(args: str) -> bool:
    """Comparing a client value to the session identity is a rejection, not a sink."""
    code = _code_outside_literals(args)
    if _COMPARISON.search(code) is None:
        return False
    return _SESSION_IDENTITY.search(code) is not None


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


def _untrusted_bound_names(source: str, seeds: set[str] | None = None) -> set[str]:
    names: set[str] = set(seeds or ())
    _absorb_assignments(source, names, lambda rhs, bound: _expression_is_untrusted(rhs, bound))
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
        r"(?:await\s+)?(?:(?:Next" + r"Response)\s*\.\s*json|JSONResponse|Response\s*\.\s*json|jsonify)\s*\(",
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


_RAW_PAYLOAD_ASSIGN = re.compile(
    r"\b([A-Za-z_][\w]*)\s*=\s*(?:await\s+)?"
    r"(?:req(?:uest)?\s*\.\s*json\s*\(|"
    r"req(?:uest)?\s*\.\s*(?:body|form|formData)\b|"
    r"formData\s*\()"
)
_IO_PASS_CALL = re.compile(
    r"(?:\.execute\s*\(|\.query\s*\(|\.insert\s*\(|\.update\s*\(|\.upsert\s*\(|"
    r"requests\.(?:post|put|patch|delete)\s*\(|httpx\.(?:post|put|patch|delete)\s*\(|"
    r"(?<![\w.])fetch\s*\(|axios\.(?:post|put|patch|delete)\s*\()",
    re.IGNORECASE,
)
_DIRECT_RAW = re.compile(
    r"req(?:uest)?\s*\.\s*json\s*\(|req(?:uest)?\s*\.\s*(?:body|form|formData)\b",
    re.IGNORECASE,
)
_FILE_WRITES = (
    re.compile(r"(?:writeFile(?:Sync)?|write_text|write_bytes)\s*\("),
    re.compile(r"(?<![\w.])open\s*\("),
)


def _raw_payload_reaches_io(source: str) -> bool:
    names = {match.group(1) for match in _RAW_PAYLOAD_ASSIGN.finditer(source)}
    for match in _IO_PASS_CALL.finditer(source):
        call = _call_from(source, match.start())
        if not call:
            continue
        inner = call[1:-1]
        if _DIRECT_RAW.search(inner):
            return True
        if any(re.search(rf"\b{re.escape(name)}\b", inner) for name in names):
            return True
    return False


def _is_tool_unit(unit: CodeUnit) -> bool:
    method = (unit.http_method or "").upper()
    if method == "TOOL" or unit.kind == "tool":
        return True
    return re.search(r"(?m)@\s*tool\b", unit.source) is not None


def _ordered_params(source: str) -> list[str]:
    signature = _first_signature(source)
    if not signature:
        return []
    names: list[str] = []
    for param in _split_top(signature, ","):
        if re.search(r"\b(?:Depends|Security)\s*\(", param):
            continue
        match = re.match(r"\s*\*{0,2}([A-Za-z_][\w]*)", param)
        if match is None:
            continue
        name = match.group(1)
        if name in {"self", "cls"}:
            continue
        names.append(name)
    return names


def _tool_param_names(unit: CodeUnit) -> set[str]:
    if not _is_tool_unit(unit):
        return set()
    return {name for name in _ordered_params(unit.source) if name not in _SKIP_PARAM_NAMES}


def _calls_dangerous_helper(unit: CodeUnit, catalog: tuple[CodeUnit, ...], seeds: set[str]) -> bool:
    grouped: dict[str, list[CodeUnit]] = {}
    for other in catalog:
        if other.unit_id == unit.unit_id:
            continue
        grouped.setdefault(other.name, []).append(other)
    if not grouped:
        return False
    bound = _untrusted_bound_names(unit.source, seeds)
    for callee, args in _iter_calls(unit.source):
        leaf = callee.split(".")[-1]
        helpers = grouped.get(leaf) or grouped.get(callee) or []
        same_file = [helper for helper in helpers if helper.file == unit.file]
        for helper in same_file or helpers:
            if _passes_untrusted_to_sink(helper, args, bound):
                return True
    return False


def _passes_untrusted_to_sink(helper: CodeUnit, args: str, bound: set[str]) -> bool:
    dangerous = _dangerous_sink_params(helper)
    if not dangerous:
        return False
    params = _ordered_params(helper.source)
    for name in dangerous:
        if _name_allowlisted(helper.source, name):
            continue
        expr = _arg_for_param(args, params, name)
        if expr and _expression_is_untrusted(expr, bound):
            return True
    return False


def _dangerous_sink_params(unit: CodeUnit) -> set[str]:
    params = set(_ordered_params(unit.source))
    if not params:
        return set()
    found: set[str] = set()
    source = unit.source
    for pattern in (*_EXEC_SINKS, _HTTP_SINK, *_FILE_WRITES):
        for match in pattern.finditer(source):
            call = _call_from(source, match.start())
            if call is None:
                continue
            if re.search(r"(?<![\w.])open\s*\($", match.group(0)) and not _open_writes(call):
                continue
            target = _read_expr(call[1:-1], 0)
            if _target_is_constant(target):
                continue
            code = _code_outside_literals(target)
            for name in params:
                if re.search(rf"\b{re.escape(name)}\b", code):
                    found.add(name)
    return found


def _open_writes(call: str) -> bool:
    return re.search(r"""['\"][wax+][^'\"]*['\"]""", call[1:-1]) is not None


def _target_is_constant(expr: str) -> bool:
    tokens = re.findall(r"[A-Za-z_][\w]*", _code_outside_literals(expr))
    return not any(token.lower() not in _TARGET_METHODS for token in tokens)


def _target_allowlisted(source: str, expr: str) -> bool:
    names = [
        token
        for token in re.findall(r"[A-Za-z_][\w]*", _code_outside_literals(expr))
        if token.lower() not in _TARGET_METHODS
    ]
    return any(_name_allowlisted(source, name) for name in names)


def _name_allowlisted(source: str, name: str) -> bool:
    code = _strip_comments(_code_outside_literals(source))
    pattern = re.compile(
        rf"\b{re.escape(name)}\b.{{0,160}}\b(?:not\s+in|in)\b.{{0,80}}\b{_ALLOWLIST_WORD}\w*\b"
        rf"|\b{_ALLOWLIST_WORD}\w*\b.{{0,120}}\b(?:has|includes|contains)\s*\(\s*{re.escape(name)}\b",
        re.IGNORECASE | re.DOTALL,
    )
    return pattern.search(code) is not None


def _arg_for_param(args: str, params: list[str], name: str) -> str | None:
    parts = [part.strip() for part in _split_top(args, ",") if part.strip()]
    positional: list[str] = []
    for part in parts:
        binding = re.match(r"([A-Za-z_][\w]*)\s*=(?!=)\s*(.*)$", part, re.DOTALL)
        if binding and binding.group(1) == name:
            return binding.group(2).strip()
        if binding is None:
            positional.append(part)
    if name not in params:
        return None
    index = params.index(name)
    if index < len(positional):
        return positional[index]
    return None


def module_risk_from_scores(scores: dict[str, float]) -> float:
    """Map the strongest rule score onto the severity question's 0..2 scale."""
    peak = max((float(value) for value in scores.values()), default=0.0)
    if peak >= 0.85:
        return 2.0
    if peak >= 0.6:
        return 1.0
    return 0.0

