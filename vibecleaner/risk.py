"""Risk tiers and which review gate a change needs.

``classify_file`` reads the path first, then lets code signals raise the tier.
A signal never lowers a tier that the path already set.

High-risk path tokens (:data:`HIGH_PATH_TOKENS`), matched on directory names
and on filename stems split by ``.``, ``_``, ``-``, and camelCase boundaries:

* auth, login, logout, session(s), oauth, admin, permissions, rbac
* billing, payment(s), checkout, stripe, webhook(s), subscription(s)
* crypto, secret(s), security
* migration(s), including ``supabase/migrations``
* the filename ``middleware.ts`` (and the same name with a JS/TS extension)

Low-risk paths: docs (``*.md``), tests, stories, styles (``*.css`` and the
common preprocessors), ``scripts/``, dev-tool config
(:data:`DEV_CONFIG_NAMES`), and UI-only components that do not touch
:data:`UI_IO_MARKERS`. Everything else is medium (API routes, data access, jobs).

Code signals that raise a file to high (:data:`HIGH_CODE_PATTERNS`, plus
``createServerClient`` used in the same file as ``auth``): ``stripe.``,
``bcrypt``, ``jwt``, ``CREATE POLICY``, ``ENABLE ROW LEVEL SECURITY``,
``DROP TABLE``, ``DELETE FROM users``.

``route_review`` then picks a gate. Tier 1 is static checks only. Tier 2 adds
automated semantic review and tests. Tier 3 is a person reading high-risk
files and any file with a critical finding. Tier 4 is an architecture and
security review when a critical finding sits in a high-risk file. A full scan
lists at most 25 of those files.
"""

from __future__ import annotations

import re
from collections import Counter
from pathlib import Path, PurePosixPath

from vibecleaner.collector import _is_test_unit_path
from vibecleaner.models import Finding, Language, ReviewRouting, RiskTier, Severity, SourceFile
from vibecleaner.preflight.code_text import code_only_text, comments_blanked, is_blankable, is_sql_path

__all__ = [
    "DEV_CONFIG_NAMES",
    "HIGH_CODE_PATTERNS",
    "HIGH_PATH_TOKENS",
    "UI_IO_MARKERS",
    "classify_file",
    "route_review",
]

_HUMAN_CAP = 25

HIGH_PATH_TOKENS: frozenset[str] = frozenset(
    {
        "auth",
        "login",
        "logout",
        "session",
        "sessions",
        "oauth",
        "admin",
        "permissions",
        "permission",
        "rbac",
        "billing",
        "payment",
        "payments",
        "checkout",
        "stripe",
        "webhook",
        "webhooks",
        "subscription",
        "subscriptions",
        "crypto",
        "secret",
        "secrets",
        "security",
        "migration",
        "migrations",
    }
)

# Next.js (and similar) auth middleware lives in this filename, not a directory.
_MIDDLEWARE_NAMES = frozenset(
    {
        "middleware.ts",
        "middleware.tsx",
        "middleware.js",
        "middleware.jsx",
        "middleware.mjs",
        "middleware.cjs",
    }
)

_DOC_SUFFIXES = frozenset({".md", ".mdx", ".rst", ".markdown"})
_STYLE_SUFFIXES = frozenset({".css", ".scss", ".sass", ".less"})
_UI_SUFFIXES = frozenset({".tsx", ".jsx"})
_UI_DIRS = frozenset({"components", "component", "ui"})
_UI_FILENAMES = frozenset(
    {
        "page.tsx",
        "page.jsx",
        "layout.tsx",
        "layout.jsx",
        "loading.tsx",
        "loading.jsx",
        "template.tsx",
        "template.jsx",
    }
)

DEV_CONFIG_NAMES: frozenset[str] = frozenset(
    {
        "vite.config.ts",
        "vite.config.js",
        "vite.config.mjs",
        "vitest.config.ts",
        "vitest.config.js",
        "jest.config.js",
        "jest.config.ts",
        "jest.config.mjs",
        "playwright.config.ts",
        "playwright.config.js",
        "eslint.config.js",
        "eslint.config.mjs",
        "eslint.config.ts",
        "prettier.config.js",
        "prettier.config.mjs",
        "tailwind.config.ts",
        "tailwind.config.js",
        "postcss.config.js",
        "postcss.config.mjs",
        "webpack.config.js",
        "rollup.config.js",
        "babel.config.js",
        "tsconfig.json",
        ".eslintrc",
        ".eslintrc.js",
        ".eslintrc.json",
        ".prettierrc",
        ".prettierrc.js",
        "stylelint.config.js",
    }
)

# Present in a component means it is not UI-only, so the file stays medium
# unless a high-risk path or code signal applies.
UI_IO_MARKERS: tuple[str, ...] = (
    "fetch(",
    "axios",
    "requests.",
    "httpx",
    "prisma",
    "supabase",
    "readFile",
    "writeFile",
    "subprocess",
    "process.env",
    "createClient(",
    "createServerClient",
)

_TOKEN_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bstripe\.", re.IGNORECASE),
    re.compile(r"\bbcrypt\b", re.IGNORECASE),
    re.compile(r"\bjwt\b", re.IGNORECASE),
)
_SQL_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"CREATE\s+POLICY\b", re.IGNORECASE),
    re.compile(r"\bENABLE\s+ROW\s+LEVEL\s+SECURITY\b", re.IGNORECASE),
    re.compile(r"\bDROP\s+TABLE\b", re.IGNORECASE),
    re.compile(r"\bDELETE\s+FROM\s+users\b", re.IGNORECASE),
)
HIGH_CODE_PATTERNS: tuple[re.Pattern[str], ...] = _TOKEN_PATTERNS + _SQL_PATTERNS

_PAYMENT_TOKENS = frozenset(
    {"billing", "payment", "payments", "checkout", "stripe", "subscription", "subscriptions"}
)
_WEBHOOK_TOKENS = frozenset({"webhook", "webhooks"})
_AUTH_TOKENS = frozenset(
    {"auth", "login", "logout", "session", "sessions", "admin", "permissions", "permission", "rbac", "oauth"}
)
_MIGRATION_TOKENS = frozenset({"migration", "migrations"})
_SECURITY_TOKENS = frozenset({"security", "secret", "secrets", "crypto"})
_JOB_TOKENS = frozenset({"job", "jobs", "worker", "workers", "queue", "queues"})
_TOKEN_SPLIT = re.compile(r"[._\-]+")
_CAMEL_SPLIT = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")
_AUTH_WORD = re.compile(r"\bauth\b", re.IGNORECASE)


def classify_file(path: str, text: str) -> RiskTier:
    """Return the risk tier of one repo-relative file.

    Docs, tests, styles and dev-tool config stay low even when their text
    mentions payment or auth APIs. Scripts can still be raised: a script that
    drops a table is high-risk.
    """
    tier = _tier_from_path(path, text)
    if _is_text_only(path):
        return tier
    if tier != RiskTier.HIGH and _code_is_high(path, text):
        return RiskTier.HIGH
    return tier


def _is_text_only(path: str) -> bool:
    return _is_non_production(path) or _is_dev_config(path)


def route_review(
    files: list[SourceFile],
    findings: list[Finding],
    changed_files: list[str] | None,
) -> ReviewRouting:
    """Pick tier 1–4 for ``changed_files``, or for every file when that is None.

    ``file_risk`` covers the considered files only. ``human_review`` is the
    high-risk files union the files with critical findings, highest tier
    first, then by finding count, capped at 25 on a full scan. The reason
    names both groups when both are present, and how many were left off.
    """
    by_path: dict[str, SourceFile] = {}
    for source in files:
        by_path.setdefault(_norm(source.path), source)
    if changed_files is None:
        considered = list(by_path)
        diff = False
    else:
        considered = []
        for path in changed_files:
            norm = _norm(path)
            if norm not in considered:
                considered.append(norm)
        diff = True
    file_risk = {
        path: classify_file(path, by_path[path].text if path in by_path else "")
        for path in considered
    }
    in_scope = [finding for finding in findings if _norm(finding.file) in file_risk]
    counts: Counter[str] = Counter(_norm(finding.file) for finding in in_scope)
    critical = [finding for finding in in_scope if finding.severity == Severity.CRITICAL]
    critical_paths = {_norm(finding.file) for finding in critical}
    high_paths = [path for path, tier in file_risk.items() if tier == RiskTier.HIGH]
    medium = any(tier == RiskTier.MEDIUM for tier in file_risk.values())
    critical_in_high = any(file_risk[path] == RiskTier.HIGH for path in critical_paths)

    if critical_in_high:
        tier = 4
    elif high_paths or critical:
        tier = 3
    elif medium or in_scope:
        tier = 2
    else:
        tier = 1
    pool = _review_pool(high_paths, critical_paths, file_risk) if tier >= 3 else []

    ordered = sorted(pool, key=lambda path: (-file_risk[path].rank, -counts[path], path))
    cap = len(ordered) > _HUMAN_CAP and not diff
    shown = ordered[:_HUMAN_CAP] if cap else ordered
    extra = len(ordered) - len(shown)
    reason = _reason(
        tier,
        ordered,
        file_risk,
        diff=diff,
        extra=extra,
        medium=medium,
        findings=bool(in_scope),
        critical_paths=critical_paths,
    )
    return ReviewRouting(tier=tier, reason=reason, file_risk=file_risk, human_review=shown)


def _tier_from_path(path: str, text: str) -> RiskTier:
    if _is_non_production(path):
        return RiskTier.LOW
    if _high_path(path):
        return RiskTier.HIGH
    if _in_scripts(path) or _is_dev_config(path):
        return RiskTier.LOW
    if _is_ui_path(path) and not _has_io(text):
        return RiskTier.LOW
    return RiskTier.MEDIUM


def _is_non_production(path: str) -> bool:
    suffix = PurePosixPath(path).suffix.lower()
    if suffix in _DOC_SUFFIXES or suffix in _STYLE_SUFFIXES:
        return True
    if _is_test_unit_path(_norm(path)):
        return True
    return _is_story(path)


def _high_path(path: str) -> bool:
    pure = PurePosixPath(_norm(path))
    if pure.name.lower() in _MIDDLEWARE_NAMES:
        return True
    return bool(_path_tokens(path) & HIGH_PATH_TOKENS)


def _path_tokens(path: str) -> set[str]:
    tokens: set[str] = set()
    for part in PurePosixPath(_norm(path)).parts:
        tokens.add(part.lower())
        stem = part.rsplit(".", 1)[0] if "." in part else part
        for piece in _TOKEN_SPLIT.split(stem):
            for word in _CAMEL_SPLIT.split(piece):
                if word:
                    tokens.add(word.lower())
    return tokens


def _in_scripts(path: str) -> bool:
    return any(part.lower() == "scripts" for part in PurePosixPath(_norm(path)).parts)


def _is_dev_config(path: str) -> bool:
    name = PurePosixPath(path).name.lower()
    if name in DEV_CONFIG_NAMES:
        return True
    return name.startswith("tsconfig.") and name.endswith(".json")


def _is_story(path: str) -> bool:
    pure = PurePosixPath(_norm(path))
    name = pure.name.lower()
    if ".stories." in name or ".story." in name:
        return True
    return any(part.lower() in {"stories", "__stories__", "storybook"} for part in pure.parts)


def _is_ui_path(path: str) -> bool:
    pure = PurePosixPath(_norm(path))
    if pure.suffix.lower() not in _UI_SUFFIXES:
        return False
    parts = {part.lower() for part in pure.parts}
    if "api" in parts:
        return False
    if parts & _UI_DIRS:
        return True
    return pure.name.lower() in _UI_FILENAMES


def _has_io(text: str) -> bool:
    return any(marker in text for marker in UI_IO_MARKERS)


def _language(path: str) -> Language:
    suffix = PurePosixPath(path).suffix.lower()
    if suffix in {".py", ".pyi", ".pyw"}:
        return Language.PYTHON
    if suffix in {".tsx", ".jsx"}:
        return Language.TSX
    if suffix in {".ts", ".mts", ".cts"}:
        return Language.TYPESCRIPT
    if suffix in {".js", ".mjs", ".cjs"}:
        return Language.JAVASCRIPT
    if suffix == ".sql":
        return Language.SQL
    return Language.OTHER


def _signal_source(path: str, text: str) -> SourceFile:
    normal = _norm(path)
    return SourceFile(path=normal, abs_path=Path(normal), language=_language(normal), text=text)


def _signal_views(path: str, text: str) -> tuple[str, str]:
    source = _signal_source(path, text)
    if is_blankable(source):
        return code_only_text(source), comments_blanked(source)
    if is_sql_path(source.path):
        stripped = comments_blanked(source)
        return stripped, stripped
    return text, text


def _code_is_high(path: str, text: str) -> bool:
    tokens, sql_text = _signal_views(path, text)
    if any(pattern.search(tokens) for pattern in _TOKEN_PATTERNS):
        return True
    if "createServerClient" in tokens and _AUTH_WORD.search(tokens) is not None:
        return True
    return any(pattern.search(sql_text) for pattern in _SQL_PATTERNS)


def _review_pool(
    high_paths: list[str],
    critical_paths: set[str],
    file_risk: dict[str, RiskTier],
) -> list[str]:
    pool: list[str] = []
    seen: set[str] = set()
    for path in high_paths + sorted(critical_paths):
        if path in seen or path not in file_risk:
            continue
        seen.add(path)
        pool.append(path)
    return pool


def _reason(
    tier: int,
    ordered: list[str],
    file_risk: dict[str, RiskTier],
    *,
    diff: bool,
    extra: int,
    medium: bool,
    findings: bool,
    critical_paths: set[str],
) -> str:
    verb = "changed" if diff else "in this scan"
    highs = [path for path in ordered if file_risk[path] == RiskTier.HIGH]
    others = [
        path for path in ordered if path in critical_paths and file_risk[path] != RiskTier.HIGH
    ]
    if tier in {3, 4} and highs and others:
        return _both_reason(highs, others, verb, extra)
    if tier == 4 and ordered:
        return _attention(ordered, verb, extra, critical=True)
    if tier == 3 and ordered:
        if highs:
            return _attention(ordered, verb, extra, critical=False)
        return _critical_reason(ordered, extra)
    if tier == 3:
        return "a critical finding needs a person to review it."
    if tier == 2:
        if medium:
            medium_paths = sorted(path for path, risk in file_risk.items() if risk == RiskTier.MEDIUM)
            target = medium_paths[0]
            return (
                f"{_medium_label(target)} {verb}: {target}; "
                "automated semantic review and tests should cover it."
            )
        return (
            f"findings {verb} in low-risk files; "
            "automated semantic review and tests should confirm them."
        )
    if not file_risk and not findings:
        return "nothing in scope and static checks passed; safe to auto-approve."
    return f"only low-risk files {verb} and static checks passed; safe to auto-approve."


def _both_reason(highs: list[str], others: list[str], verb: str, extra: int) -> str:
    if extra or len(highs) == 1:
        high_names = highs[0]
    else:
        high_names = _file_phrase(highs, 0)
    target = others[0]
    if len(others) == 1:
        critical = f"critical finding in {target}"
    else:
        critical = f"critical finding in {target} and {len(others) - 1} more"
    lead = f"{_shared_label(highs)} {verb}: {high_names}; {critical}"
    tail = "a person should read them"
    if extra:
        return f"{lead}; {tail}, {extra} more not listed."
    return f"{lead}; {tail}."


def _critical_reason(paths: list[str], extra: int) -> str:
    target = paths[0]
    if extra:
        return f"critical finding in {target}; a person should review it, {extra} more not listed."
    if len(paths) == 1:
        return f"critical finding in {target}; a person should review it."
    rest = len(paths) - 1
    return f"critical finding in {target} and {rest} more; a person should review them."


def _attention(paths: list[str], verb: str, extra: int, *, critical: bool) -> str:
    label = _shared_label(paths)
    listed = _file_phrase(paths, extra)
    if critical:
        lead = f"critical finding in high-risk {label} {listed}"
    else:
        lead = f"{label} {verb}: {listed}"
    tail = "a person should read it" if len(paths) == 1 and extra == 0 else "a person should read them"
    if extra:
        return f"{lead}; {tail}, {extra} more not listed."
    return f"{lead}; {tail}."


def _file_phrase(paths: list[str], extra: int) -> str:
    if extra:
        return paths[0]
    if len(paths) == 1:
        return paths[0]
    if len(paths) == 2:
        return f"{paths[0]} and {paths[1]}"
    head = ", ".join(paths[:3])
    rest = len(paths) - 3
    if rest:
        return f"{head}, and {rest} more"
    return head


def _shared_label(paths: list[str]) -> str:
    labels = {_area_label(path) for path in paths}
    if len(labels) == 1:
        return next(iter(labels))
    return "high-risk code"


def _area_label(path: str) -> str:
    tokens = _path_tokens(path)
    if tokens & _PAYMENT_TOKENS:
        return "payments code"
    if tokens & _WEBHOOK_TOKENS:
        return "webhook code"
    if tokens & _AUTH_TOKENS or PurePosixPath(path).name.lower() in _MIDDLEWARE_NAMES:
        return "auth code"
    if tokens & _MIGRATION_TOKENS:
        return "migration code"
    if tokens & _SECURITY_TOKENS:
        return "security-sensitive code"
    return "high-risk code"


def _medium_label(path: str) -> str:
    pure = PurePosixPath(path)
    parts = {part.lower() for part in pure.parts}
    if "api" in parts or pure.name.lower().startswith("route."):
        return "api code"
    if parts & _JOB_TOKENS:
        return "job code"
    return "medium-risk code"


def _norm(path: str) -> str:
    return path.replace("\\", "/")
