"""Process environment and the Gemini client shared by the judge and the patcher."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from google.genai.client import Client

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


def genai_client(key: str | None, *, api_version: str | None = None) -> Client:
    """Build a google-genai client. The SDK import stays inside this function.

    Decision calls pass ``api_version`` (``v1beta``). Patch generation omits it,
    which is a different constructor call than passing ``http_options``.
    """
    from google import genai

    if api_version is None:
        return genai.Client(api_key=key)
    return genai.Client(api_key=key, http_options={"api_version": api_version})
