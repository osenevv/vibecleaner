"""Runtime settings loaded from the process environment."""

from __future__ import annotations

import os
from dataclasses import dataclass

REQUIRED = (
    "OPENAI_API_KEY",
    "SUPABASE_URL",
    "SUPABASE_SERVICE_ROLE_KEY",
    "DATABASE_URL",
    "INTERNAL_API_SECRET",
)


@dataclass(frozen=True)
class Settings:
    app_env: str
    openai_api_key: str
    openai_model: str
    supabase_url: str
    supabase_service_role_key: str
    database_url: str
    internal_api_secret: str
    receipts_from: str
    default_currency: str
    request_timeout_ms: int


def load_settings() -> Settings:
    missing = [name for name in REQUIRED if not os.environ.get(name, "").strip()]
    if missing:
        joined = ", ".join(missing)
        raise RuntimeError(f"missing environment variables: {joined}")
    return Settings(
        app_env=os.environ.get("APP_ENV", "production"),
        openai_api_key=os.environ["OPENAI_API_KEY"],
        openai_model=os.environ.get("OPENAI_MODEL", "gpt-4o-mini"),
        supabase_url=os.environ["SUPABASE_URL"],
        supabase_service_role_key=os.environ["SUPABASE_SERVICE_ROLE_KEY"],
        database_url=os.environ["DATABASE_URL"],
        internal_api_secret=os.environ["INTERNAL_API_SECRET"],
        receipts_from=os.environ.get("RECEIPTS_FROM", "receipts@northwind.dev"),
        default_currency=os.environ.get("DEFAULT_CURRENCY", "usd"),
        request_timeout_ms=int(os.environ.get("REQUEST_TIMEOUT_MS", "8000")),
    )
