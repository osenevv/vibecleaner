from __future__ import annotations

from datetime import datetime
from zoneinfo import ZoneInfo

from roster.shifts import still_on_shift


def test_evening_utc_is_before_a_new_york_close() -> None:
    now = datetime(2026, 1, 15, 22, 0, tzinfo=ZoneInfo("UTC"))
    shift_end = datetime(2026, 1, 15, 18, 30, tzinfo=ZoneInfo("America/New_York"))
    assert still_on_shift(now, shift_end) is True


def test_valid_input_same_zone_before_close() -> None:
    zone = ZoneInfo("UTC")
    now = datetime(2026, 1, 15, 12, 0, tzinfo=zone)
    shift_end = datetime(2026, 1, 15, 17, 0, tzinfo=zone)
    assert still_on_shift(now, shift_end) is True
