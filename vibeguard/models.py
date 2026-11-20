"""Shared schema contract for every VibeGuard layer.

Layer 1 (collector + deterministic), Layer 2 (decision_judge + cache) and
Layer 3 (reporter + patcher) only exchange the types defined here.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def rank(self) -> int:
        return {"critical": 4, "high": 3, "medium": 2, "low": 1}[self.value]


class Category(str, Enum):
    SECURITY = "security"
    SLOP = "slop"


class Language(str, Enum):
    PYTHON = "python"
    TYPESCRIPT = "typescript"
    TSX = "tsx"
    JAVASCRIPT = "javascript"
    SQL = "sql"
    ENV = "env"
    OTHER = "other"


@dataclass(frozen=True)
class RuleSpec:
    rule_id: str
    detector: str
    title: str
    category: Category
    severity: Severity
    layer: int
    remediation: str
    question: str | None = None
    true_description: str | None = None
    false_description: str | None = None


# Layer 2 questions are formatted with `module=<unit label>` (e.g. "MOD_07").
# The Decisions API never shows question keys to the model, so every question
# must name the module it is about inside its own instructions.
RULES: dict[str, RuleSpec] = {
    spec.rule_id: spec
    for spec in [
        RuleSpec(
            "D1.env_file_committed", "D1", "Committed .env file", Category.SECURITY, Severity.CRITICAL, 1,
            "Remove the file from git, rotate every credential in it, and add `.env*` to .gitignore (keep `.env.example`).",
        ),
        RuleSpec(
            "D1.next_public_secret", "D1", "Private key exposed via NEXT_PUBLIC_ variable", Category.SECURITY, Severity.CRITICAL, 1,
            "NEXT_PUBLIC_* values are inlined into the browser bundle. Rename the variable without the prefix and read it only in server code; rotate the key.",
        ),
        RuleSpec(
            "D1.hardcoded_secret", "D1", "Hardcoded secret literal", Category.SECURITY, Severity.CRITICAL, 1,
            "Move the value to an environment variable or secret manager and rotate it.",
        ),
        RuleSpec(
            "D2.supabase_missing_rls", "D2", "Supabase table without row level security", Category.SECURITY, Severity.CRITICAL, 1,
            "Add `ALTER TABLE <t> ENABLE ROW LEVEL SECURITY;` in the same migration.",
        ),
        RuleSpec(
            "D2.supabase_missing_policy", "D2", "Supabase table with RLS but no policy", Category.SECURITY, Severity.HIGH, 1,
            "Add explicit `CREATE POLICY` statements scoped to `auth.uid()` for each operation the app needs.",
        ),
        RuleSpec(
            "D2.cors_wildcard_credentials", "D2", "Wildcard CORS with credentials", Category.SECURITY, Severity.HIGH, 1,
            "List explicit trusted origins; browsers must never receive `*` together with credentials.",
        ),
        RuleSpec(
            "D6a.silent_exception", "D6a", "Silently swallowed exception", Category.SLOP, Severity.MEDIUM, 1,
            "Catch the narrowest exception type and log, re-raise, or handle it explicitly.",
        ),
        RuleSpec(
            "D6a.god_file", "D6a", "God file mixing DB, HTTP and business logic", Category.SLOP, Severity.MEDIUM, 1,
            "Split routing, persistence and domain logic into separate modules.",
        ),
        RuleSpec(
            "D6a.deprecated_sdk", "D6a", "Deprecated or hallucinated SDK call", Category.SLOP, Severity.HIGH, 1,
            "Use the current SDK API (e.g. `client.chat.completions.create`, Pydantic v2 `model_dump()` / `field_validator`).",
        ),
        RuleSpec(
            "D6a.passthrough_wrapper", "D6a", "Pass-through wrapper", Category.SLOP, Severity.LOW, 1,
            "Call the wrapped function directly or give the wrapper a real responsibility.",
        ),
        RuleSpec(
            "D6c.llm_prose", "D6c", "LLM prose tic", Category.SLOP, Severity.LOW, 1,
            "State the fact in plain technical prose. A hit is a candidate: quoted specimens and the author's own voice are not tics.",
        ),
        RuleSpec(
            "D8.unbounded_retry", "D8", "Retry cannot reach a terminal state", Category.SLOP, Severity.HIGH, 1,
            "Bound the attempts and raise, return, or break on the last failure so a caught error cannot spin forever.",
        ),
        RuleSpec(
            "D8.retry_falls_through", "D8", "Retry ends as success after every attempt failed", Category.SLOP, Severity.HIGH, 1,
            "After the last caught failure, raise or return an error. Do not fall out of the loop into the caller's success path.",
        ),
        RuleSpec(
            "D8.lock_not_released", "D8", "Lock acquired without a release path", Category.SLOP, Severity.HIGH, 1,
            "Acquire inside a with-statement, or release in a finally that runs on every exit after the acquire.",
        ),
        RuleSpec(
            "D3.missing_auth", "D3", "Missing authentication on mutating route", Category.SECURITY, Severity.CRITICAL, 2,
            "Require an authenticated session (route dependency, middleware matcher, or explicit session check) before the mutation.",
            question=(
                "Considering GLOBAL_AUTH_CONTEXT (middleware matchers and router-level dependencies) and any auth check inside "
                "{module}, can an unauthenticated caller trigger a database write, state mutation, or paid external API call in {module}?"
            ),
            true_description="No effective auth check applies to the mutating code path in this module.",
            false_description="The module is read-only, or an upstream/global or local auth check protects every mutation.",
        ),
        RuleSpec(
            "D4.idor_or_price_trust", "D4", "Client-side trust (IDOR / price tampering)", Category.SECURITY, Severity.CRITICAL, 2,
            "Derive user/org identity from the verified session and prices from the server-side catalogue, never from the request body.",
            question=(
                "In {module}, does the handler trust user_id, org_id, role, is_admin, or price/amount values taken directly from "
                "the client request (body, query, or params) instead of deriving identity or pricing on the server?"
            ),
            true_description="Identity, role, or price comes from client-controlled input and is used for authorization, ownership, or charging.",
            false_description="Identity comes from the verified session/token and prices from server-side data, or the module has no such values.",
        ),
        RuleSpec(
            "D5.prompt_injection", "D5", "Prompt injection / unbounded tool call", Category.SECURITY, Severity.CRITICAL, 2,
            "Keep user text in the user role, validate tool arguments against a schema, and gate state-mutating tools behind an allow-list or approval step.",
            question=(
                "In {module}, is raw untrusted user input concatenated into LLM system instructions, or passed to state-mutating "
                "tool calls (SQL, shell, file write, webhook) without schema validation or an approval gate?"
            ),
            true_description="Untrusted text reaches the system prompt or an unvalidated mutating tool/exec/SQL call.",
            false_description="User text stays in the user role and tool calls are validated, allow-listed, or read-only; or no LLM is used.",
        ),
        RuleSpec(
            "D6b.hardcoded_mock_stub", "D6b", "Fake or stubbed production logic", Category.SLOP, Severity.HIGH, 2,
            "Implement the real logic or fail loudly (raise / 501) instead of returning placeholder data.",
            question=(
                "In {module} (a non-test production code path), does the function return hardcoded mock or placeholder data, "
                "or leave its core logic unimplemented (TODO stub, NotImplemented, fake success)?"
            ),
            true_description="The production path returns fake/static data or a stub instead of doing its job.",
            false_description="The code performs its real work (static constants such as config or enums are fine).",
        ),
        RuleSpec(
            "D7a.n_plus_one_loop", "D7a", "N+1 queries or unbounded query", Category.SLOP, Severity.MEDIUM, 2,
            "Batch the lookups (IN query, join, Promise.all with a bounded pool) and paginate or LIMIT unbounded selects.",
            question=(
                "In {module}, does the code execute database queries or external HTTP/network calls sequentially inside a "
                "for/while loop or .map()/.forEach() callback, or query an entire table without pagination or LIMIT?"
            ),
            true_description="There is a per-item query/fetch inside a loop, or an unbounded full-table select.",
            false_description="Queries are batched, joined, paginated, or there are no loops over I/O.",
        ),
        RuleSpec(
            "D7b.missing_boundary_schema", "D7b", "Missing boundary validation", Category.SLOP, Severity.MEDIUM, 2,
            "Validate the request at the boundary with a typed schema (Pydantic model / Zod schema) before using it.",
            question=(
                "In {module}, does an HTTP or tool entrypoint accept a raw unvalidated payload (dict, Any, request.json(), "
                "req.body) and use its fields without enforcing a typed schema such as a Pydantic model or Zod schema?"
            ),
            true_description="Request data is consumed as an untyped dict/any without schema validation.",
            false_description="The entrypoint validates input with Pydantic/Zod/typed models, or the module has no external entrypoint.",
        ),
    ]
}

LAYER2_RULE_IDS: tuple[str, ...] = tuple(r.rule_id for r in RULES.values() if r.layer == 2)

# Short question-key suffixes for the Decisions API (keys must match [A-Za-z0-9_-]+).
LAYER2_KEY_SUFFIX: dict[str, str] = {
    "D3.missing_auth": "missing_auth",
    "D4.idor_or_price_trust": "idor_or_price_trust",
    "D5.prompt_injection": "prompt_injection",
    "D6b.hardcoded_mock_stub": "hardcoded_mock_stub",
    "D7a.n_plus_one_loop": "n_plus_one_loop",
    "D7b.missing_boundary_schema": "missing_boundary_schema",
}

SEVERITY_QUESTION_CRITERIA: list[str] = [
    "Clean: proper auth (local or upstream), boundary validation, and real production logic.",
    "Medium: engineering slop (N+1 loop, missing schema validation, or stubbed fallback).",
    "Critical: auth bypass, IDOR/price tampering, prompt injection, or fake production endpoint.",
]

DEFAULT_THRESHOLD = 0.75
FIX_THRESHOLD = 0.85


@dataclass
class SourceFile:
    path: str  # repo-relative POSIX path
    abs_path: Path
    language: Language
    text: str

    @property
    def line_count(self) -> int:
        return self.text.count("\n") + (0 if self.text.endswith("\n") or not self.text else 1)


@dataclass
class CodeUnit:
    """A function/handler-level slice sent to Layer 2 (never whole files)."""

    file: str
    language: Language
    name: str
    kind: str  # "route" | "function" | "module"
    start_line: int  # 1-based, inclusive
    end_line: int  # 1-based, inclusive
    source: str
    http_method: str | None = None
    route_path: str | None = None
    label: str = ""  # "MOD_01".. assigned per Layer 2 chunk

    @property
    def unit_id(self) -> str:
        return f"{self.file}:{self.start_line}:{self.name}"

    def content_hash(self, auth_context: str) -> str:
        return hashlib.sha256((auth_context + "\n\x00\n" + self.source).encode("utf-8")).hexdigest()

    def contains_line(self, line: int) -> bool:
        return self.start_line <= line <= self.end_line


@dataclass
class ScanContext:
    root: Path
    files: list[SourceFile]
    units: list[CodeUnit]  # Layer 2 candidates (mutating routes + core functions), already diff-filtered
    auth_context: str  # GLOBAL_AUTH_CONTEXT text (~500 tokens max)
    diff_base: str | None = None
    changed_files: list[str] | None = None  # None means full scan


@dataclass
class Finding:
    rule_id: str
    file: str
    line: int
    message: str
    end_line: int | None = None
    symbol: str | None = None
    probability: float | None = None  # Layer 2 calibrated noul; None for Layer 1 (exact)
    snippet: str | None = None
    fix_patch: str | None = None  # unified diff from patcher (--fix)
    module_risk: float | None = None  # Layer 2 `severity` score question: expected level 0 (clean) .. 2 (critical)

    @property
    def spec(self) -> RuleSpec:
        return RULES[self.rule_id]

    @property
    def severity(self) -> Severity:
        return self.spec.severity

    @property
    def category(self) -> Category:
        return self.spec.category

    @property
    def layer(self) -> int:
        return self.spec.layer

    @property
    def detector(self) -> str:
        return self.spec.detector


@dataclass
class JudgeStats:
    mode: str = "disabled"  # "live" | "offline" | "disabled"
    units_judged: int = 0
    units_skipped_layer1: int = 0
    cache_hits: int = 0
    requests: int = 0
    input_tokens: int = 0
    errors: list[str] = field(default_factory=list)


@dataclass
class ScanResult:
    root: Path
    findings: list[Finding]
    files_scanned: int
    judge: JudgeStats
    duration_s: float
    diff_base: str | None = None
