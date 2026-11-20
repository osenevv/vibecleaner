"""Load North Barn after-hours pager settings from the process environment.

Operators export the variables in ``.env`` before the pager process starts.
This module only reads those names; it does not embed credential literals.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


def _required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"missing environment variable {name}")
    return value


@dataclass(frozen=True)
class PagerSettings:
    database_url: str
    openai_api_key: str
    supabase_service_role_key: str
    pager_webhook_secret: str
    clinic_name: str
    pager_from_number: str
    quiet_hours_start: str
    quiet_hours_end: str


def load_settings() -> PagerSettings:
    return PagerSettings(
        database_url=_required("DATABASE_URL"),
        openai_api_key=_required("OPENAI_API_KEY"),
        supabase_service_role_key=_required("SUPABASE_SERVICE_ROLE_KEY"),
        pager_webhook_secret=_required("PAGER_WEBHOOK_SECRET"),
        clinic_name=os.environ.get("CLINIC_NAME", "North Barn Veterinary"),
        pager_from_number=_required("PAGER_FROM_NUMBER"),
        quiet_hours_start=os.environ.get("QUIET_HOURS_START", "22:00"),
        quiet_hours_end=os.environ.get("QUIET_HOURS_END", "06:00"),
    )
