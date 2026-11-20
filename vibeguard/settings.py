"""Process environment shared by the decision judge and the patcher."""

from __future__ import annotations

import os

_API_KEY_VARS = ("GEMINI_API_KEY", "GOOGLE_API_KEY")
DEFAULT_FIX_MODEL = "gemini-2.5-flash"


def api_key() -> str | None:
    """Return the first non-empty Gemini/Google API key, or None."""
    for name in _API_KEY_VARS:
        value = os.environ.get(name, "").strip()
        if value:
            return value
    return None


def fix_model() -> str:
    """Model used to draft unified diffs. Override with ``VIBEGUARD_FIX_MODEL``."""
    value = os.environ.get("VIBEGUARD_FIX_MODEL", "").strip()
    return value or DEFAULT_FIX_MODEL
