"""Read cafeteria process configuration. Secrets stay in the environment."""

from __future__ import annotations

import os
from dataclasses import dataclass


def _required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"missing environment variable {name}")
    return value


@dataclass(frozen=True)
class CafeteriaSettings:
    database_url: str
    vendor_secret: str
    menu_timezone: str
    max_meal_swipes: int


def load_settings() -> CafeteriaSettings:
    return CafeteriaSettings(
        database_url=_required("DATABASE_URL"),
        vendor_secret=_required("LUNCH_VENDOR_SECRET"),
        menu_timezone=os.environ.get("MENU_TIMEZONE", "America/Chicago"),
        max_meal_swipes=int(os.environ.get("MAX_MEAL_SWIPES", "2")),
    )
