from __future__ import annotations

from datetime import datetime, timedelta, timezone

from roster.shifts import still_on_shift

_UTC = timezone.utc
_NEW_YORK = timezone(timedelta(hours=-5))


def test_evening_utc_is_before_a_new_york_close() -> None:
    now = datetime(2026, 1, 15, 22, 0, tzinfo=_UTC)
    shift_end = datetime(2026, 1, 15, 18, 30, tzinfo=_NEW_YORK)
    assert still_on_shift(now, shift_end) is True


def test_valid_input_same_zone_before_close() -> None:
    now = datetime(2026, 1, 15, 12, 0, tzinfo=_UTC)
    shift_end = datetime(2026, 1, 15, 17, 0, tzinfo=_UTC)
    assert still_on_shift(now, shift_end) is True
