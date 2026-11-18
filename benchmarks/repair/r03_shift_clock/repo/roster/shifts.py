from __future__ import annotations

from datetime import datetime


def still_on_shift(now: datetime, shift_end: datetime) -> bool:
    if now.tzinfo is None or shift_end.tzinfo is None:
        raise ValueError("both times need a timezone")
    return now.replace(tzinfo=None) < shift_end.replace(tzinfo=None)
