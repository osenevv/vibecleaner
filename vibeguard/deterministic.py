"""Layer 1 exact checks. No model calls; precision outranks recall."""

from __future__ import annotations

import base64
import binascii
import math
import re
from collections import Counter
from pathlib import PurePosixPath

import tree_sitter_python
import tree_sitter_typescript
from tree_sitter import Language as TSLanguage
from tree_sitter import Node, Parser

from vibeguard.models import Finding, Language, ScanContext, SourceFile

__all__ = [
    "detect_cors",
    "detect_deprecated_sdk",
    "detect_god_file",
    "detect_passthrough_wrappers",
    "detect_secrets",
    "detect_silent_exceptions",
    "detect_supabase_rls",
    "detect_supabase_rls_all",
    "run_deterministic",
    "shannon_entropy",
]

_PY_LANGUAGE = TSLanguage(tree_sitter_python.language())
_TS_LANGUAGE = TSLanguage(tree_sitter_typescript.language_typescript())
_TSX_LANGUAGE = TSLanguage(tree_sitter_typescript.language_tsx())
_PY_PARSER = Parser(_PY_LANGUAGE)
_TS_PARSER = Parser(_TS_LANGUAGE)
_TSX_PARSER = Parser(_TSX_LANGUAGE)

_CODE_LANGS = frozenset({Language.PYTHON, Language.TYPESCRIPT, Language.TSX, Language.JAVASCRIPT})
_BROAD_EXCEPTIONS = frozenset({"Exception", "BaseException"})
_SKIP_WRAPPER_DECORATORS = frozenset({"property", "abstractmethod", "overload"})
_HTTP_NAMES = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE"})
_HTTP_JSON_RECEIVERS = frozenset({"response", "resp", "res", "req", "request", "session", "r"})
_ENV_EXAMPLE_NAMES = frozenset({".env.example", ".env.sample", ".env.template"})
_PLACEHOLDER_WORDS = ("your", "xxx", "example", "changeme", "dummy", "placeholder", "test")
_PUBLIC_OK_SUFFIXES = ("PUBLISHABLE_KEY", "PUBLIC_KEY", "SITE_KEY", "ANON_KEY")
_PUBLIC_BAD = (
    "SERVICE_ROLE",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "STRIPE_SECRET",
    "DATABASE_URL",
    "PASSWORD",
    "PRIVATE",
    "SECRET",
    "TOKEN",
    "SK_",
)

_ENV_LINE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$")
_NEXT_PUBLIC = re.compile(r"\bNEXT_PUBLIC_[A-Z0-9_]+\b")
_SENSITIVE_NAME = re.compile(
    r"(secret|token|api_?key|apikey|password|passwd|private_?key|access_?key|client_?secret|auth)",
    re.IGNORECASE,
)
_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_QUOTED_ASSIGN = re.compile(
    r"""(?P<key>[A-Za-z_][A-Za-z0-9_.-]*)['\"]?\s*[:=]\s*(?P<q>['\"])(?P<val>[^'\"\n]{20,200})(?P=q)"""
)

_ORIGIN_HEADER = "Access-Control-Allow-" + "Origin"
_CRED_HEADER = "Access-Control-Allow-" + "Credentials"

_SQL_IDENT = r'(?:"[^"]+"|[A-Za-z_][\w$]*)'
_SQL_QNAME = rf"(?:{_SQL_IDENT}\s*\.\s*)?{_SQL_IDENT}"
_CREATE_TABLE = re.compile(rf"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?({_SQL_QNAME})", re.IGNORECASE)
_ENABLE_RLS = re.compile(
    rf"ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?({_SQL_QNAME})\s+ENABLE\s+ROW\s+LEVEL\s+SECURITY",
    re.IGNORECASE,
)
_CREATE_POLICY = re.compile(
    rf"CREATE\s+POLICY\s+(?:\"[^\"]+\"|\S+)\s+ON\s+({_SQL_QNAME})",
    re.IGNORECASE,
)

# Patterns are concatenated so this file does not contain the literal it searches for.
_KNOWN_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private_key", re.compile("-----BEGIN " + r"(?:RSA |EC |OPENSSH )?" + "PRIVATE KEY-----")),
    ("anthropic", re.compile("sk-" + "ant-" + r"[A-Za-z0-9_-]{20,}")),
    ("openai", re.compile("sk-" + r"(?:proj-)?" + r"[A-Za-z0-9_-]{20,}")),
    ("stripe", re.compile("sk_" + "live_" + r"[0-9A-Za-z]{16,}")),
    ("stripe", re.compile("rk_" + "live_" + r"[0-9A-Za-z]{16,}")),
    ("aws", re.compile("AKIA" + r"[0-9A-Z]{16}")),
    ("github", re.compile(r"gh[pousr]_" + r"[A-Za-z0-9]{36,}")),
    ("slack", re.compile(r"xox[baprs]-" + r"[A-Za-z0-9-]{10,}")),
    ("google", re.compile("AIza" + r"[0-9A-Za-z_-]{35}")),
    (
        "supabase_service_role",
        re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    ),
)

_DB_RE = re.compile(
    "|".join(
        [
            "exec" + r"ute\(",
            "session" + r"\.query",
            r"\.qu" + r"ery\(",
            "(?:SEL" + "ECT|INS" + "ERT|UPD" + r"ATE)\s+\S",
            "supa" + r"base\.from",
            "pris" + r"ma\.",
            r"\b" + "db" + r"\.",
        ]
    )
)
_HTTP_RE = re.compile(
    "|".join(
        [
            r"@\w+\.(?:get|post|put|patch|delete|api_route|websocket)\(",
            r"\b(?:app|router)\.(?:get|post|put|patch|delete|all)\(",
            "Next" + "Res" + "ponse",
            r"(?::\s*|->\s*)" + "Re" + r"quest\b",
            r"(?::\s*|->\s*)(?:Next)?" + "Res" + r"ponse\b",
            "API" + r"Router\(",
            "exp" + r"ress\(",
            r"\b" + "Rou" + r"ter\(",
        ]
    )
)

_LEGACY_CALLS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "openai." + "ChatCompletion.create",
        re.compile(r"openai\." + "Chat" + r"Completion\.create"),
    ),
    (
        "openai." + "Completion.create",
        re.compile(r"openai\." + r"(?<!Chat)Completion\.create"),
    ),
    (
        "openai." + "Embedding.create",
        re.compile(r"openai\." + "Embed" + r"ding\.create"),
    ),
    (
        "openai." + "Image.create",
        re.compile(r"openai\." + "Im" + r"age\.create"),
    ),
    (
        "openai." + "api_key assignment",
        re.compile(r"openai\." + r"api_key\s*="),
    ),
    (
        "from langchain" + ".llms import",
        re.compile(r"from\s+langchain" + r"\.llms\s+import\b"),
    ),
    (
        "from langchain" + ".chat_models import",
        re.compile(r"from\s+langchain" + r"\.chat_models\s+import\b"),
    ),
    (
        "LLM" + "Chain(",
        re.compile(r"\bLLM" + r"Chain\s*\("),
    ),
    (
        "initialize" + "_agent(",
        re.compile(r"\binitialize" + r"_agent\s*\("),
    ),
)
_LEGACY_TS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "new " + "OpenAIApi(",
        re.compile(r"\bnew\s+" + "OpenAI" + r"Api\s*\("),
    ),
    (
        ".create" + "ChatCompletion(",
        re.compile(r"\.create" + "Chat" + r"Completion\s*\("),
    ),
    (
        ".create" + "Completion(",
        re.compile(r"\.create" + r"Completion\s*\("),
    ),
)
_PYDANTIC_VALIDATOR = re.compile(r"@(\w+\.)?" + "valida" + r"tor\b")
_PYDANTIC_ROOT_VALIDATOR = re.compile(r"@(\w+\.)?" + "root_valida" + r"tor\b")


def shannon_entropy(s: str) -> float:
    """Shannon entropy in bits per character. Empty input is 0."""
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def run_deterministic(ctx: ScanContext) -> list[Finding]:
    """Run every Layer 1 rule over ``ctx.files`` and return a stable, deduped list."""
    findings: list[Finding] = []
    for source in ctx.files:
        findings.extend(detect_secrets(source))
        findings.extend(detect_cors(source))
        findings.extend(detect_silent_exceptions(source))
        findings.extend(detect_god_file(source))
        findings.extend(detect_deprecated_sdk(source))
        findings.extend(detect_passthrough_wrappers(source))
    # RLS is decided across the whole migration set: a later file may enable it.
    findings.extend(detect_supabase_rls_all(ctx.files))
    return _dedupe(findings)


def detect_secrets(f: SourceFile) -> list[Finding]:
    findings: list[Finding] = []
    if f.language == Language.ENV:
        findings.extend(_env_file_committed(f))
    findings.extend(_next_public(f))
    if f.language == Language.ENV or _is_secret_test_path(f.path):
        return findings
    findings.extend(_hardcoded(f))
    return findings


def detect_supabase_rls(f: SourceFile) -> list[Finding]:
    """Single-file convenience wrapper around :func:`detect_supabase_rls_all`."""
    return detect_supabase_rls_all([f])


def detect_supabase_rls_all(files: list[SourceFile]) -> list[Finding]:
    relevant = [source for source in files if _sql_in_scope(source)]
    if not relevant:
        return []
    stripped = [(source, _strip_sql_comments(source.text)) for source in relevant]
    enabled: set[str] = set()
    policies: set[str] = set()
    for _source, text in stripped:
        for match in _ENABLE_RLS.finditer(text):
            enabled.add(_table_key(match.group(1)))
        for match in _CREATE_POLICY.finditer(text):
            policies.add(_table_key(match.group(1)))
    findings: list[Finding] = []
    for source, text in stripped:
        for match in _CREATE_TABLE.finditer(text):
            schema, name = _split_table(match.group(1))
            if schema not in {None, "public"} or not name:
                continue
            line = text.count("\n", 0, match.start()) + 1
            if name not in enabled:
                findings.append(
                    _finding(
                        "D2.supabase_missing_rls",
                        source,
                        line,
                        f"Table {name} has no ENABLE ROW LEVEL SECURITY",
                        symbol=name,
                    )
                )
            elif name not in policies:
                findings.append(
                    _finding(
                        "D2.supabase_missing_policy",
                        source,
                        line,
                        f"Table {name} has row level security enabled but no CREATE POLICY",
                        symbol=name,
                    )
                )
    return findings


def detect_cors(f: SourceFile) -> list[Finding]:
    findings: list[Finding] = []
    lines: set[int] = set()
    if f.language == Language.PYTHON:
        lines.update(_python_cors_lines(f))
    elif f.language in {Language.TYPESCRIPT, Language.TSX, Language.JAVASCRIPT}:
        lines.update(_script_cors_lines(f))
    header_line = _header_wildcard_line(f.text)
    if header_line is not None:
        lines.add(header_line)
    for line in sorted(lines):
        findings.append(
            _finding(
                "D2.cors_wildcard_credentials",
                f,
                line,
                "Wildcard CORS origin is combined with credentialed responses",
            )
        )
    return findings


def detect_silent_exceptions(f: SourceFile) -> list[Finding]:
    if f.language not in _CODE_LANGS:
        return []
    parser = _parser_for(f)
    if parser is None:
        return []
    tree = parser.parse(f.text.encode("utf-8"))
    if f.language == Language.PYTHON:
        return _python_silent(f, tree.root_node)
    return _script_silent(f, tree.root_node)


def detect_god_file(f: SourceFile) -> list[Finding]:
    if f.language not in _CODE_LANGS:
        return []
    nonblank = sum(1 for line in f.text.splitlines() if line.strip())
    if nonblank <= 500:
        return []
    if _DB_RE.search(f.text) is None or _HTTP_RE.search(f.text) is None:
        return []
    functions = _count_non_route_functions(f)
    if functions < 8:
        return []
    return [
        _finding(
            "D6a.god_file",
            f,
            1,
            (
                "God file mixes DB, HTTP, and business logic "
                f"({nonblank} non-blank lines, {functions} non-route functions)"
            ),
        )
    ]


def detect_deprecated_sdk(f: SourceFile) -> list[Finding]:
    if f.language == Language.PYTHON:
        return _deprecated_python(f)
    if f.language in {Language.TYPESCRIPT, Language.TSX, Language.JAVASCRIPT}:
        return _deprecated_script(f)
    return []


def detect_passthrough_wrappers(f: SourceFile) -> list[Finding]:
    if f.language not in _CODE_LANGS:
        return []
    parser = _parser_for(f)
    if parser is None:
        return []
    tree = parser.parse(f.text.encode("utf-8"))
    if f.language == Language.PYTHON:
        return _python_wrappers(f, tree.root_node)
    return _script_wrappers(f, tree.root_node)


def _env_file_committed(f: SourceFile) -> list[Finding]:
    keys: list[str] = []
    seen: set[str] = set()
    for line in f.text.splitlines():
        match = _ENV_LINE.match(line)
        if match is None:
            continue
        key, raw = match.group(1), match.group(2)
        if key in seen or not _env_value_nonempty(raw):
            continue
        seen.add(key)
        keys.append(key)
    if not keys:
        return []
    shown = keys[:5]
    extra = len(keys) - len(shown)
    message = "Committed env file defines " + ", ".join(shown)
    if extra:
        message += f" (+{extra} more)"
    snippet = _mask_env_line(_line_text(f.text, 1))
    return [_finding("D1.env_file_committed", f, 1, message, snippet=snippet)]


def _env_value_nonempty(raw: str) -> bool:
    value = raw.strip()
    if not value or value.startswith("#"):
        return False
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        value = value[1:-1].strip()
    return value != ""


def _next_public(f: SourceFile) -> list[Finding]:
    by_line: dict[int, list[str]] = {}
    for match in _NEXT_PUBLIC.finditer(f.text):
        name = match.group(0)
        if not _next_public_is_secret(name):
            continue
        line = f.text.count("\n", 0, match.start()) + 1
        names = by_line.setdefault(line, [])
        if name not in names:
            names.append(name)
    findings: list[Finding] = []
    for line, names in by_line.items():
        snippet = _mask_quoted(_line_text(f.text, line))
        findings.append(
            _finding(
                "D1.next_public_secret",
                f,
                line,
                "Browser-exposed variable " + ", ".join(names) + " looks like a private credential",
                snippet=snippet,
            )
        )
    return findings


def _next_public_is_secret(name: str) -> bool:
    if any(name.endswith(suffix) for suffix in _PUBLIC_OK_SUFFIXES):
        return False
    return any(bad in name for bad in _PUBLIC_BAD)


def _hardcoded(f: SourceFile) -> list[Finding]:
    grouped: dict[int, list[tuple[str, str]]] = {}
    for start, value, kind in _known_hits(f.text):
        line = f.text.count("\n", 0, start) + 1
        grouped.setdefault(line, []).append((value, kind))
    if not _is_env_example(f.path):
        for line, value, _key in _entropy_hits(f):
            grouped.setdefault(line, []).append((value, "high-entropy"))
    findings: list[Finding] = []
    for line, hits in grouped.items():
        kind = next((item_kind for _value, item_kind in hits if item_kind != "high-entropy"), "high-entropy")
        values = [value for value, _item_kind in hits]
        snippet = _mask_values(_line_text(f.text, line), values)
        findings.append(_finding("D1.hardcoded_secret", f, line, f"Hardcoded secret ({kind})", snippet=snippet))
    return findings


def _known_hits(text: str) -> list[tuple[int, str, str]]:
    found: list[tuple[int, int, str, str]] = []
    for kind, pattern in _KNOWN_PATTERNS:
        for match in pattern.finditer(text):
            value = match.group(0)
            if kind == "supabase_service_role" and not _jwt_is_service_role(value):
                continue
            # Anthropic keys also match the broader OpenAI prefix; keep the specific hit.
            if kind == "openai" and value.startswith("sk-" + "ant-"):
                continue
            found.append((match.start(), match.end(), value, kind))
    found.sort(key=lambda item: (item[0], -(item[1] - item[0])))
    kept: list[tuple[int, str, str]] = []
    last_end = -1
    for start, end, value, kind in found:
        if start < last_end:
            continue
        kept.append((start, value, kind))
        last_end = end
    return kept


def _jwt_is_service_role(token: str) -> bool:
    parts = token.split(".")
    if len(parts) < 2:
        return False
    payload = parts[1]
    padded = payload + ("=" * (-len(payload) % 4))
    try:
        decoded = base64.urlsafe_b64decode(padded)
    except (binascii.Error, ValueError):
        return False
    text = decoded.decode("utf-8", errors="replace")
    return re.search(r'"role"\s*:\s*"service_role"', text) is not None


def _entropy_hits(f: SourceFile) -> list[tuple[int, str, str]]:
    if f.language == Language.PYTHON:
        return _python_entropy(f)
    if f.language in {Language.TYPESCRIPT, Language.TSX, Language.JAVASCRIPT}:
        return _script_entropy(f)
    return _regex_entropy(f.text)


def _accept_entropy(value: str, key: str) -> bool:
    if not 20 <= len(value) <= 200 or any(char.isspace() for char in value):
        return False
    if shannon_entropy(value) <= 4.3 or _SENSITIVE_NAME.search(key) is None:
        return False
    lowered = value.lower()
    if any(word in lowered for word in _PLACEHOLDER_WORDS) or "<" in value or "${" in value:
        return False
    if _UUID.match(value):
        return False
    if re.fullmatch(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", value) and re.search(
        r"(hash|sha|checksum|integrity)", key, re.IGNORECASE
    ):
        return False
    if _url_without_credentials(value):
        return False
    return True


def _url_without_credentials(value: str) -> bool:
    if re.match(r"https?://", value, re.IGNORECASE) is None:
        return False
    return re.match(r"https?://[^/\s:@]+:[^/\s@]+@", value, re.IGNORECASE) is None


def _python_entropy(f: SourceFile) -> list[tuple[int, str, str]]:
    tree = _PY_PARSER.parse(f.text.encode("utf-8"))
    hits: list[tuple[int, str, str]] = []

    def bind(name: str, value_node: Node) -> None:
        if value_node.type != "string":
            return
        value = _python_string(value_node)
        if value is not None and _accept_entropy(value, name):
            hits.append((value_node.start_point[0] + 1, value, name))

    def walk(node: Node) -> None:
        if node.type == "assignment":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left is not None and right is not None:
                if left.type == "identifier":
                    bind(_text(left), right)
                elif left.type == "attribute":
                    attr = left.child_by_field_name("attribute")
                    if attr is not None:
                        bind(_text(attr), right)
        elif node.type == "keyword_argument" and node.named_children:
            name_node = node.named_children[0]
            value_node = node.named_children[-1]
            if name_node.type == "identifier":
                bind(_text(name_node), value_node)
        elif node.type == "pair":
            key = node.child_by_field_name("key")
            value = node.child_by_field_name("value")
            if key is not None and value is not None:
                key_name = _python_string(key) if key.type == "string" else _text(key)
                if key_name:
                    bind(key_name, value)
        elif node.type == "call":
            _python_getenv(node, hits)
        for child in node.named_children:
            walk(child)

    walk(tree.root_node)
    return hits


def _python_getenv(call: Node, hits: list[tuple[int, str, str]]) -> None:
    func = call.child_by_field_name("function")
    if func is None:
        return
    callee = _dotted(func)
    if callee not in {"os.getenv", "getenv", "os.environ.get"}:
        return
    args = call.child_by_field_name("arguments")
    if args is None:
        return
    strings = [child for child in args.named_children if child.type == "string"]
    if len(strings) < 2:
        return
    key = _python_string(strings[0])
    value = _python_string(strings[1])
    if key and value and _accept_entropy(value, key):
        hits.append((strings[1].start_point[0] + 1, value, key))


def _script_entropy(f: SourceFile) -> list[tuple[int, str, str]]:
    parser = _parser_for(f)
    if parser is None:
        return []
    tree = parser.parse(f.text.encode("utf-8"))
    hits: list[tuple[int, str, str]] = []

    def bind(name: str, value_node: Node) -> None:
        value = _script_string(value_node)
        if value is not None and _accept_entropy(value, name):
            hits.append((value_node.start_point[0] + 1, value, name))

    def walk(node: Node) -> None:
        if node.type == "variable_declarator":
            name_node = node.child_by_field_name("name")
            value = node.child_by_field_name("value")
            if name_node is not None and name_node.type == "identifier" and value is not None:
                bind(_text(name_node), value)
        elif node.type == "assignment_expression":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left is not None and right is not None:
                if left.type == "identifier":
                    bind(_text(left), right)
                elif left.type == "member_expression":
                    prop = left.child_by_field_name("property")
                    if prop is not None:
                        bind(_text(prop), right)
        elif node.type == "pair":
            key = node.child_by_field_name("key")
            value = node.child_by_field_name("value")
            if key is not None and value is not None:
                key_name = _script_string(key) if key.type == "string" else _text(key)
                if key_name:
                    bind(key_name, value)
        elif node.type == "binary_expression":
            _script_env_fallback(node, hits)
        for child in node.named_children:
            walk(child)

    walk(tree.root_node)
    return hits


def _script_env_fallback(node: Node, hits: list[tuple[int, str, str]]) -> None:
    operator = node.child_by_field_name("operator")
    if operator is None or _text(operator) not in {"??", "||"}:
        return
    left = node.child_by_field_name("left")
    right = node.child_by_field_name("right")
    if left is None or right is None:
        return
    name = _process_env_name(left)
    value = _script_string(right)
    if name and value and _accept_entropy(value, name):
        hits.append((right.start_point[0] + 1, value, name))


def _process_env_name(node: Node) -> str | None:
    if node.type == "member_expression":
        obj = node.child_by_field_name("object")
        prop = node.child_by_field_name("property")
        if obj is not None and prop is not None and _text(obj) == "process.env":
            return _text(prop)
    if node.type == "subscript_expression":
        obj = node.child_by_field_name("object")
        index = node.child_by_field_name("index")
        if obj is not None and index is not None and _text(obj) == "process.env":
            return _script_string(index)
    return None


def _regex_entropy(text: str) -> list[tuple[int, str, str]]:
    hits: list[tuple[int, str, str]] = []
    for match in _QUOTED_ASSIGN.finditer(text):
        key = match.group("key")
        value = match.group("val")
        if _accept_entropy(value, key):
            hits.append((text.count("\n", 0, match.start()) + 1, value, key))
    return hits


def _sql_in_scope(source: SourceFile) -> bool:
    if source.language != Language.SQL and not source.path.endswith(".sql"):
        return False
    path = source.path
    if "/migrations/" in f"/{path}" or path.startswith("migrations/"):
        return True
    lowered = source.text.lower()
    return "auth.uid()" in lowered or "supabase" in lowered


def _strip_sql_comments(sql: str) -> str:
    out: list[str] = []
    index = 0
    limit = len(sql)
    while index < limit:
        if sql.startswith("--", index):
            while index < limit and sql[index] != "\n":
                out.append(" ")
                index += 1
            continue
        if sql.startswith("/*", index):
            end = sql.find("*/", index + 2)
            end = limit if end < 0 else end + 2
            out.append(re.sub(r"[^\n]", " ", sql[index:end]))
            index = end
            continue
        dollar = re.match(r"\$[A-Za-z_]*\$", sql[index:])
        if dollar is not None:
            tag = dollar.group(0)
            end = sql.find(tag, index + len(tag))
            end = limit if end < 0 else end + len(tag)
            out.append(re.sub(r"[^\n]", " ", sql[index:end]))
            index = end
            continue
        if sql[index] in {"'", '"'}:
            quote = sql[index]
            out.append(quote)
            index += 1
            while index < limit:
                out.append(sql[index])
                if sql[index] == quote:
                    if quote == "'" and index + 1 < limit and sql[index + 1] == "'":
                        out.append(sql[index + 1])
                        index += 2
                        continue
                    index += 1
                    break
                index += 1
            continue
        out.append(sql[index])
        index += 1
    return "".join(out)


def _split_table(qname: str) -> tuple[str | None, str]:
    parts = _split_qualified(qname)
    if len(parts) >= 2:
        return _unquote(parts[-2]).lower(), _unquote(parts[-1]).lower()
    if not parts:
        return None, ""
    return None, _unquote(parts[0]).lower()


def _table_key(qname: str) -> str:
    _schema, name = _split_table(qname)
    return name


def _split_qualified(qname: str) -> list[str]:
    parts: list[str] = []
    current: list[str] = []
    index = 0
    in_quote = False
    while index < len(qname):
        char = qname[index]
        if char == '"':
            in_quote = not in_quote
            current.append(char)
        elif char == "." and not in_quote:
            parts.append("".join(current).strip())
            current = []
        else:
            current.append(char)
        index += 1
    tail = "".join(current).strip()
    if tail:
        parts.append(tail)
    return parts


def _unquote(token: str) -> str:
    token = token.strip()
    if len(token) >= 2 and token[0] == '"' and token[-1] == '"':
        return token[1:-1].replace('""', '"')
    return token


def _python_cors_lines(f: SourceFile) -> list[int]:
    tree = _PY_PARSER.parse(f.text.encode("utf-8"))
    lines: list[int] = []

    def walk(node: Node) -> None:
        if node.type == "call" and _python_cors_call(node):
            lines.append(node.start_point[0] + 1)
        for child in node.named_children:
            walk(child)

    walk(tree.root_node)
    return lines


def _python_cors_call(call: Node) -> bool:
    func = call.child_by_field_name("function")
    if func is None:
        return False
    name = _dotted(func)
    text = _text(call)
    interesting = name.endswith("add_middleware") and "CORS" + "Middleware" in text
    interesting = interesting or name == "CORS" or name.endswith(".CORS")
    interesting = interesting or name.endswith("CORS" + "Middleware")
    return interesting and _python_cors_dangerous(text)


def _python_cors_dangerous(call: str) -> bool:
    if re.search(r"\b(?:allow_credentials|supports_credentials)\s*=\s*True\b", call) is None:
        return False
    if re.search(r"""\ballow_origin_regex\s*=\s*(['\"])\.\*\1""", call):
        return True
    match = re.search(r"\b(?:allow_origins|origins)\s*=\s*(.{0,500})", call, re.DOTALL)
    if match is None:
        return False
    value = re.split(r",\s*[A-Za-z_][\w]*\s*=", match.group(1), maxsplit=1)[0]
    return re.search(r"""(['\"])\*\1""", value) is not None


def _script_cors_lines(f: SourceFile) -> list[int]:
    parser = _parser_for(f)
    if parser is None:
        return []
    tree = parser.parse(f.text.encode("utf-8"))
    lines: list[int] = []

    def walk(node: Node) -> None:
        if node.type == "call_expression" and _script_cors_call(node):
            lines.append(node.start_point[0] + 1)
        for child in node.named_children:
            walk(child)

    walk(tree.root_node)
    return lines


def _script_cors_call(call: Node) -> bool:
    func = call.child_by_field_name("function")
    if func is None or _attr_leaf(func) != "cors":
        return False
    args = call.child_by_field_name("arguments")
    if args is None:
        return False
    for child in args.named_children:
        if child.type == "object" and _cors_object(child):
            return True
    return False


def _cors_object(obj: Node) -> bool:
    origin: Node | None = None
    credentials: Node | None = None
    for pair in obj.named_children:
        if pair.type != "pair":
            continue
        key = pair.child_by_field_name("key")
        value = pair.child_by_field_name("value")
        if key is None or value is None:
            continue
        name = _script_string(key) if key.type == "string" else _text(key)
        if name == "origin":
            origin = value
        elif name == "credentials":
            credentials = value
    if origin is None or credentials is None or credentials.type != "true":
        return False
    if origin.type == "true":
        return True
    if origin.type == "string":
        return _script_string(origin) == "*"
    if origin.type == "array":
        return any(child.type == "string" and _script_string(child) == "*" for child in origin.named_children)
    return False


def _header_wildcard_line(text: str) -> int | None:
    origin_line: int | None = None
    credentials = False
    rows = text.splitlines()
    for index, line in enumerate(rows):
        window = "\n".join(rows[index : index + 4])
        if _ORIGIN_HEADER in line and re.search(r"""['\"]\*['\"]""", window):
            origin_line = origin_line or (index + 1)
        if _CRED_HEADER in line and re.search(r"\btrue\b", window, re.IGNORECASE):
            credentials = True
    if origin_line is not None and credentials:
        return origin_line
    return None


def _python_silent(f: SourceFile, root: Node) -> list[Finding]:
    findings: list[Finding] = []

    def walk(node: Node) -> None:
        if node.type == "except_clause" and _broad_except(node) and _python_body_silent(node):
            findings.append(
                _finding(
                    "D6a.silent_exception",
                    f,
                    node.start_point[0] + 1,
                    "Broad except swallows the error without logging or re-raising",
                )
            )
        for child in node.named_children:
            walk(child)

    walk(root)
    return findings


def _broad_except(clause: Node) -> bool:
    names: list[str] = []
    for child in clause.named_children:
        if child.type == "block":
            continue
        names.extend(_exception_names(child))
    if not names:
        return True
    return any(name in _BROAD_EXCEPTIONS for name in names)


def _exception_names(node: Node) -> list[str]:
    if node.type == "identifier":
        return [_text(node)]
    if node.type == "attribute":
        return [_attr_leaf(node)]
    if node.type == "tuple":
        names: list[str] = []
        for child in node.named_children:
            names.extend(_exception_names(child))
        return names
    if node.type == "as_pattern" and node.named_children:
        return _exception_names(node.named_children[0])
    return []


def _python_body_silent(clause: Node) -> bool:
    block = next((child for child in clause.named_children if child.type == "block"), None)
    if block is None or not block.named_children:
        return False
    return all(_python_stmt_silent(stmt) for stmt in block.named_children)


def _python_stmt_silent(stmt: Node) -> bool:
    if stmt.type in {"pass_statement", "continue_statement", "comment"}:
        return True
    if stmt.type == "expression_statement" and stmt.named_children:
        inner = stmt.named_children[0]
        return inner.type in {"ellipsis", "string"}
    if stmt.type == "return_statement":
        values = stmt.named_children
        return not values or (len(values) == 1 and values[0].type == "none")
    return False


def _script_silent(f: SourceFile, root: Node) -> list[Finding]:
    findings: list[Finding] = []

    def walk(node: Node) -> None:
        if node.type == "catch_clause":
            body = node.child_by_field_name("body")
            if body is not None and body.type == "statement_block" and _block_empty(body):
                findings.append(
                    _finding(
                        "D6a.silent_exception",
                        f,
                        node.start_point[0] + 1,
                        "Empty catch swallows the error",
                    )
                )
        elif node.type == "call_expression" and _is_empty_promise_catch(node):
            findings.append(
                _finding(
                    "D6a.silent_exception",
                    f,
                    node.start_point[0] + 1,
                    "Empty .catch() swallows the rejection",
                )
            )
        for child in node.named_children:
            walk(child)

    walk(root)
    return findings


def _block_empty(block: Node) -> bool:
    return not [child for child in block.named_children if child.type != "comment"]


def _is_empty_promise_catch(call: Node) -> bool:
    func = call.child_by_field_name("function")
    if func is None or func.type != "member_expression":
        return False
    prop = func.child_by_field_name("property")
    if prop is None or _text(prop) != "catch":
        return False
    args = call.child_by_field_name("arguments")
    if args is None or not args.named_children:
        return False
    callback = args.named_children[0]
    if callback.type != "arrow_function":
        return False
    body = callback.child_by_field_name("body")
    if body is None:
        return False
    if body.type in {"null", "undefined"}:
        return True
    if body.type == "identifier" and _text(body) == "undefined":
        return True
    if body.type != "statement_block":
        return False
    statements = [child for child in body.named_children if child.type != "comment"]
    if not statements:
        return True
    return all(_script_stmt_silent(stmt) for stmt in statements)


def _script_stmt_silent(stmt: Node) -> bool:
    if stmt.type in {"comment", "empty_statement"}:
        return True
    if stmt.type != "return_statement":
        return False
    values = stmt.named_children
    if not values:
        return True
    if len(values) == 1 and values[0].type in {"null", "undefined"}:
        return True
    return len(values) == 1 and values[0].type == "identifier" and _text(values[0]) == "undefined"


def _count_non_route_functions(f: SourceFile) -> int:
    parser = _parser_for(f)
    if parser is None:
        return 0
    tree = parser.parse(f.text.encode("utf-8"))
    count = 0
    for node in _walk(tree.root_node):
        if f.language == Language.PYTHON and node.type == "function_definition":
            if not _python_route_function(node):
                count += 1
        elif node.type in {"function_declaration", "method_definition"}:
            name_node = node.child_by_field_name("name")
            name = _text(name_node) if name_node is not None else ""
            if name not in _HTTP_NAMES:
                count += 1
        elif node.type == "variable_declarator":
            name_node = node.child_by_field_name("name")
            value = node.child_by_field_name("value")
            if (
                name_node is not None
                and name_node.type == "identifier"
                and value is not None
                and value.type in {"arrow_function", "function_expression"}
                and _text(name_node) not in _HTTP_NAMES
            ):
                count += 1
    return count


def _python_route_function(func: Node) -> bool:
    parent = func.parent
    if parent is None or parent.type != "decorated_definition":
        return False
    for decorator in parent.named_children:
        if decorator.type != "decorator":
            continue
        leaf = _decorator_leaf(decorator)
        if leaf in {"get", "post", "put", "patch", "delete", "api_route", "websocket", "tool"}:
            return True
    return False


def _deprecated_python(f: SourceFile) -> list[Finding]:
    findings = _regex_deprecated(f, _LEGACY_CALLS)
    imports_pydantic = re.search(r"^\s*(?:import\s+pydantic\b|from\s+pydantic\b)", f.text, re.MULTILINE) is not None
    if not imports_pydantic:
        return findings
    seen = {finding.line for finding in findings}
    for index, line in enumerate(f.text.splitlines(), start=1):
        if index in seen:
            continue
        if _PYDANTIC_ROOT_VALIDATOR.search(line) or _PYDANTIC_VALIDATOR.search(line):
            findings.append(_finding("D6a.deprecated_sdk", f, index, "Deprecated SDK usage: Pydantic v1 validator"))
            seen.add(index)
    has_model = re.search(r"\bBase" + r"Model\b", f.text) is not None
    tree = _PY_PARSER.parse(f.text.encode("utf-8"))
    for line, message in _pydantic_ast(tree.root_node, has_model):
        if line in seen:
            continue
        findings.append(_finding("D6a.deprecated_sdk", f, line, message))
        seen.add(line)
    return findings


def _pydantic_ast(root: Node, has_model: bool) -> list[tuple[int, str]]:
    hits: list[tuple[int, str]] = []

    def walk(node: Node, in_model: bool) -> None:
        if node.type == "class_definition":
            name_node = node.child_by_field_name("name")
            name = _text(name_node) if name_node is not None else ""
            bases = node.child_by_field_name("superclasses")
            extends = bases is not None and "Base" + "Model" in _text(bases)
            if name == "Config" and in_model:
                hits.append((node.start_point[0] + 1, "Deprecated SDK usage: Pydantic v1 Config class"))
            body = node.child_by_field_name("body")
            if body is not None:
                for child in body.named_children:
                    walk(child, extends or in_model)
            return
        if node.type == "call" and has_model:
            func = node.child_by_field_name("function")
            if func is not None and func.type == "attribute":
                method_node = func.child_by_field_name("attribute")
                receiver = func.child_by_field_name("object")
                method = _text(method_node) if method_node is not None else ""
                if method in {"parse_obj", "parse_raw", "dict", "json"} and _pydantic_method_counts(method, receiver):
                    hits.append((node.start_point[0] + 1, f"Deprecated SDK usage: .{method}()"))
        for child in node.named_children:
            walk(child, in_model)

    walk(root, False)
    return hits


def _pydantic_method_counts(method: str, receiver: Node | None) -> bool:
    if method in {"parse_obj", "parse_raw", "dict"}:
        return True
    if receiver is None or receiver.type == "call":
        return False
    name = _text(receiver) if receiver.type == "identifier" else _attr_leaf(receiver)
    return name not in _HTTP_JSON_RECEIVERS


def _deprecated_script(f: SourceFile) -> list[Finding]:
    findings = _regex_deprecated(f, _LEGACY_TS)
    if re.search(r"\bOpenAI" + r"Api\b", f.text) is None:
        return findings
    if re.search(r"""from\s+['\"]openai['\"]""", f.text) is None:
        return findings
    configuration = "Config" + "uration"
    seen = {finding.line for finding in findings}
    for index, line in enumerate(f.text.splitlines(), start=1):
        if index in seen or configuration not in line:
            continue
        findings.append(_finding("D6a.deprecated_sdk", f, index, "Deprecated SDK usage: openai Configuration import"))
        seen.add(index)
    return findings


def _regex_deprecated(f: SourceFile, patterns: tuple[tuple[str, re.Pattern[str]], ...]) -> list[Finding]:
    by_line: dict[int, str] = {}
    for label, pattern in patterns:
        for match in pattern.finditer(f.text):
            line = f.text.count("\n", 0, match.start()) + 1
            by_line.setdefault(line, label)
    return [_finding("D6a.deprecated_sdk", f, line, f"Deprecated SDK usage: {label}") for line, label in by_line.items()]


def _python_wrappers(f: SourceFile, root: Node) -> list[Finding]:
    findings: list[Finding] = []

    def walk(node: Node) -> None:
        if node.type == "function_definition":
            finding = _python_wrapper(f, node)
            if finding is not None:
                findings.append(finding)
        for child in node.named_children:
            walk(child)

    walk(root)
    return findings


def _python_wrapper(f: SourceFile, func: Node) -> Finding | None:
    name_node = func.child_by_field_name("name")
    name = _text(name_node) if name_node is not None else ""
    if not name or (name.startswith("__") and name.endswith("__")):
        return None
    if _skip_wrapper_decorator(func):
        return None
    params = func.child_by_field_name("parameters")
    body = func.child_by_field_name("body")
    if params is None or body is None:
        return None
    forwarded = _forward_names(params)
    if forwarded is None or not _python_forwards(body, forwarded[0], forwarded[1]):
        return None
    return _finding(
        "D6a.passthrough_wrapper",
        f,
        func.start_point[0] + 1,
        f"Pass-through wrapper {name} only forwards its arguments",
        symbol=name,
    )


def _skip_wrapper_decorator(func: Node) -> bool:
    parent = func.parent
    if parent is None or parent.type != "decorated_definition":
        return False
    for decorator in parent.named_children:
        if decorator.type == "decorator" and _decorator_leaf(decorator) in _SKIP_WRAPPER_DECORATORS:
            return True
    return False


def _forward_names(params: Node) -> tuple[str, str] | None:
    named = list(params.named_children)
    if named and named[0].type == "identifier" and _text(named[0]) in {"self", "cls"}:
        named = named[1:]
    if len(named) != 2:
        return None
    star, kw = named
    if star.type != "list_splat_pattern" or kw.type != "dictionary_splat_pattern":
        return None
    if not star.named_children or not kw.named_children:
        return None
    return _text(star.named_children[0]), _text(kw.named_children[0])


def _python_forwards(body: Node, star: str, kw: str) -> bool:
    statements: list[Node] = []
    for child in body.named_children:
        if not statements and _is_docstring(child):
            continue
        statements.append(child)
    if len(statements) != 1:
        return False
    stmt = statements[0]
    if stmt.type == "return_statement":
        values = stmt.named_children
        return len(values) == 1 and _is_python_forward(values[0], star, kw)
    if stmt.type == "expression_statement" and stmt.named_children:
        return _is_python_forward(stmt.named_children[0], star, kw)
    return False


def _is_docstring(stmt: Node) -> bool:
    return stmt.type == "expression_statement" and bool(stmt.named_children) and stmt.named_children[0].type == "string"


def _is_python_forward(node: Node, star: str, kw: str) -> bool:
    if node.type == "await":
        calls = [child for child in node.named_children if child.type == "call"]
        return len(calls) == 1 and _is_python_forward(calls[0], star, kw)
    if node.type != "call":
        return False
    args = node.child_by_field_name("arguments")
    if args is None or len(args.named_children) != 2:
        return False
    left, right = args.named_children
    if left.type != "list_splat" or right.type != "dictionary_splat":
        return False
    if not left.named_children or not right.named_children:
        return False
    return _text(left.named_children[0]) == star and _text(right.named_children[0]) == kw


def _script_wrappers(f: SourceFile, root: Node) -> list[Finding]:
    findings: list[Finding] = []
    for node in _walk(root):
        found = _script_wrapper(f, node)
        if found is not None:
            findings.append(found)
    return findings


def _script_wrapper(f: SourceFile, node: Node) -> Finding | None:
    if node.type not in {"function_declaration", "function_expression", "arrow_function", "method_definition"}:
        return None
    named = _script_wrapper_name(node)
    if named is None:
        return None
    name, line = named
    if name.startswith("__") and name.endswith("__"):
        return None
    params = node.child_by_field_name("parameters")
    if params is None:
        return None
    rest = _rest_name(params)
    if rest is None or not _script_forwards(node, rest):
        return None
    return _finding(
        "D6a.passthrough_wrapper",
        f,
        line,
        f"Pass-through wrapper {name} only forwards its arguments",
        symbol=name,
    )


def _script_wrapper_name(node: Node) -> tuple[str, int] | None:
    if node.type in {"function_declaration", "method_definition", "function_expression"}:
        name_node = node.child_by_field_name("name")
        if name_node is not None:
            return _text(name_node), node.start_point[0] + 1
        parent = node.parent
        if parent is not None and parent.type == "variable_declarator":
            parent_name = parent.child_by_field_name("name")
            if parent_name is not None and parent_name.type == "identifier":
                return _text(parent_name), parent.start_point[0] + 1
        return None
    parent = node.parent
    if parent is None or parent.type != "variable_declarator":
        return None
    name_node = parent.child_by_field_name("name")
    if name_node is None or name_node.type != "identifier":
        return None
    return _text(name_node), parent.start_point[0] + 1


def _rest_name(params: Node) -> str | None:
    named = params.named_children
    if len(named) != 1:
        return None
    param = named[0]
    rest = param if param.type == "rest_pattern" else None
    if param.type == "required_parameter":
        rest = next((child for child in param.named_children if child.type == "rest_pattern"), None)
    if rest is None:
        return None
    ident = next((child for child in rest.named_children if child.type == "identifier"), None)
    if ident is None:
        return None
    return _text(ident)


def _script_forwards(func: Node, rest: str) -> bool:
    body = func.child_by_field_name("body")
    if body is None:
        return False
    if body.type == "call_expression":
        return _is_script_forward_call(body, rest)
    if body.type != "statement_block":
        return False
    statements = [child for child in body.named_children if child.type != "comment"]
    if len(statements) != 1:
        return False
    stmt = statements[0]
    if stmt.type == "return_statement":
        values = stmt.named_children
        return len(values) == 1 and _is_script_forward_call(values[0], rest)
    if stmt.type == "expression_statement" and stmt.named_children:
        return _is_script_forward_call(stmt.named_children[0], rest)
    return False


def _is_script_forward_call(node: Node, rest: str) -> bool:
    if node.type == "await_expression" and node.named_children:
        return _is_script_forward_call(node.named_children[-1], rest)
    if node.type != "call_expression":
        return False
    args = node.child_by_field_name("arguments")
    if args is None or len(args.named_children) != 1:
        return False
    spread = args.named_children[0]
    if spread.type != "spread_element" or not spread.named_children:
        return False
    ident = spread.named_children[0]
    return ident.type == "identifier" and _text(ident) == rest


def _is_secret_test_path(path: str) -> bool:
    parts = PurePosixPath(path).parts
    if any(part in {"tests", "fixtures", "__mocks__"} for part in parts):
        return True
    name = parts[-1] if parts else path
    if name.startswith("test_"):
        return True
    return ".test." in name or ".spec." in name


def _is_env_example(path: str) -> bool:
    return PurePosixPath(path).name in _ENV_EXAMPLE_NAMES


def _parser_for(source: SourceFile) -> Parser | None:
    if source.language == Language.PYTHON:
        return _PY_PARSER
    if source.language == Language.TSX or source.path.endswith(".jsx"):
        return _TSX_PARSER
    if source.language in {Language.TYPESCRIPT, Language.JAVASCRIPT}:
        return _TS_PARSER
    return None


def _decorator_leaf(decorator: Node) -> str:
    inner = decorator.named_children[0] if decorator.named_children else None
    if inner is None:
        return ""
    if inner.type == "call":
        func = inner.child_by_field_name("function")
        return _attr_leaf(func) if func is not None else ""
    return _attr_leaf(inner)


def _attr_leaf(node: Node) -> str:
    if node.type in {"identifier", "property_identifier"}:
        return _text(node)
    if node.type == "attribute":
        attr = node.child_by_field_name("attribute")
        return _text(attr) if attr is not None else ""
    if node.type == "member_expression":
        prop = node.child_by_field_name("property")
        return _text(prop) if prop is not None else ""
    if node.type == "call":
        func = node.child_by_field_name("function")
        return _attr_leaf(func) if func is not None else ""
    if node.type == "call_expression":
        func = node.child_by_field_name("function")
        return _attr_leaf(func) if func is not None else ""
    return ""


def _dotted(node: Node) -> str:
    if node.type == "identifier":
        return _text(node)
    if node.type == "attribute":
        obj = node.child_by_field_name("object")
        attr = node.child_by_field_name("attribute")
        if obj is None or attr is None:
            return ""
        return _dotted(obj) + "." + _text(attr)
    return ""


def _walk(node: Node) -> list[Node]:
    nodes: list[Node] = []
    stack = [node]
    while stack:
        current = stack.pop()
        nodes.append(current)
        stack.extend(reversed(current.named_children))
    return nodes


def _text(node: Node) -> str:
    raw = node.text
    if isinstance(raw, bytes):
        return raw.decode("utf-8", errors="replace")
    return str(raw)


def _python_string(node: Node) -> str | None:
    if node.type != "string" or any(child.type == "interpolation" for child in node.children):
        return None
    return "".join(_text(child) for child in node.children if child.type == "string_content")


def _script_string(node: Node) -> str | None:
    if node.type == "string":
        if any(child.is_named and child.type != "string_fragment" for child in node.children):
            return None
        return "".join(_text(child) for child in node.children if child.type == "string_fragment")
    if node.type == "template_string":
        if any(child.type == "template_substitution" for child in node.children):
            return None
        return "".join(_text(child) for child in node.children if child.type == "string_fragment")
    return None


def _line_text(text: str, line: int) -> str:
    rows = text.splitlines()
    if 1 <= line <= len(rows):
        return rows[line - 1].strip()
    return ""


def _mask(value: str) -> str:
    return f"{value[:4]}…{len(value)}"


def _mask_values(line: str, values: list[str]) -> str:
    masked = line
    for value in sorted({item for item in values if item}, key=len, reverse=True):
        if value in masked:
            masked = masked.replace(value, _mask(value))
    return masked


def _mask_quoted(line: str) -> str:
    def replace(match: re.Match[str]) -> str:
        inner = match.group(2)
        if len(inner) < 6:
            return match.group(0)
        return match.group(1) + _mask(inner) + match.group(1)

    return re.sub(r"(['\"])([^'\"]+)\1", replace, line)


def _mask_env_line(line: str) -> str:
    match = re.match(r"^(\s*(?:export\s+)?[A-Za-z_][\w]*\s*=\s*)(.*)$", line.strip())
    if match is None:
        return line.strip()
    prefix, raw = match.group(1), match.group(2).strip()
    if not raw or raw.startswith("#"):
        return line.strip()
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in {"'", '"'}:
        inner = raw[1:-1]
        if not inner:
            return line.strip()
        return prefix + raw[0] + _mask(inner) + raw[0]
    return prefix + _mask(raw)


def _finding(
    rule_id: str,
    source: SourceFile,
    line: int,
    message: str,
    *,
    symbol: str | None = None,
    snippet: str | None = None,
) -> Finding:
    if snippet is None:
        snippet = _line_text(source.text, line)
    return Finding(rule_id=rule_id, file=source.path, line=line, message=message, symbol=symbol, snippet=snippet)


def _dedupe(findings: list[Finding]) -> list[Finding]:
    ordered = sorted(findings, key=lambda finding: (finding.file, finding.line, finding.rule_id))
    seen: set[tuple[str, str, int]] = set()
    unique: list[Finding] = []
    for finding in ordered:
        key = (finding.rule_id, finding.file, finding.line)
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique
