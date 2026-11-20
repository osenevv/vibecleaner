"""Replace secret values before they are sent to a model or written to a report."""

from __future__ import annotations

import re
from collections.abc import Callable

_KNOWN_SECRETS = (
    re.compile(r"sk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}"),
    re.compile(r"\b(?:ghp|gho|github_pat)_[A-Za-z0-9_]{16,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}"),
)
_SENSITIVE_KEY = re.compile(
    r"(?:^|_)(?:secret|token|password|passwd|pwd|apikey|api_key|private_key|access_key|"
    r"client_secret|auth_token|credential|credentials|dsn|database_url|service_role|"
    r"signing_key|webhook_secret)(?:_|$)",
    re.IGNORECASE,
)
_ASSIGNED = re.compile(
    r"""(?P<prefix>\b(?P<key>[A-Za-z_][\w.-]*)\s*[:=]\s*)"""
    r"""(?:(?P<q>['\"])(?P<quoted>[^'\"\n]{8,})(?P=q)|(?P<bare>[^\s#'\",;)\]}]{8,}))"""
)


def redact_secrets(text: str) -> str:
    """Replace secret values with ``<redacted:N chars>``.

    Uses ``vibeguard.deterministic.mask_secrets`` when that helper is available.
    """
    external = _external_mask()
    if external is not None:
        return external(text)
    masked = text
    for pattern in _KNOWN_SECRETS:
        masked = pattern.sub(lambda match: _token(match.group(0)), masked)
    return _ASSIGNED.sub(_replace_assignment, masked)


def _external_mask() -> Callable[[str], str] | None:
    try:
        from vibeguard import deterministic
    except ImportError:
        return None
    fn = getattr(deterministic, "mask_secrets", None)
    if callable(fn):
        return fn
    return None


def _key_sensitive(key: str) -> bool:
    try:
        from vibeguard import deterministic
    except ImportError:
        return _SENSITIVE_KEY.search(key) is not None
    checker = getattr(deterministic, "_key_is_sensitive", None)
    if not callable(checker):
        return _SENSITIVE_KEY.search(key) is not None
    return bool(checker(key))


def _replace_assignment(match: re.Match[str]) -> str:
    key = match.group("key")
    if not _key_sensitive(key):
        return match.group(0)
    value = match.group("quoted") or match.group("bare") or ""
    if value.startswith("<redacted:"):
        return match.group(0)
    quote = match.group("q") or ""
    return f"{match.group('prefix')}{quote}{_token(value)}{quote}"


def _token(value: str) -> str:
    return f"<redacted:{len(value)} chars>"
