"""Settings loader. Secrets come from the environment, never from this file."""

from __future__ import annotations

import os
from dataclasses import dataclass

REQUIRED = (
    "OPENAI_API_KEY",
    "SUPABASE_URL",
    "DATABASE_URL",
)


@dataclass(frozen=True)
class Settings:
    app_env: str
    openai_api_key: str
    supabase_url: str
    database_url: str
    request_timeout_ms: int


def _required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"missing environment variable {name}")
    return value


def load_settings() -> Settings:
    missing = [name for name in REQUIRED if not os.environ.get(name, "").strip()]
    if missing:
        raise RuntimeError("missing environment variables: " + ", ".join(missing))
    return Settings(
        app_env=os.environ.get("APP_ENV", "development"),
        openai_api_key=_required("OPENAI_API_KEY"),
        supabase_url=_required("SUPABASE_URL"),
        database_url=_required("DATABASE_URL"),
        request_timeout_ms=int(os.environ.get("REQUEST_TIMEOUT_MS", "8000")),
    )
