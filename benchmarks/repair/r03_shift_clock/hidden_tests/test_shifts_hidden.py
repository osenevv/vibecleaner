from __future__ import annotations

from datetime import datetime
from zoneinfo import ZoneInfo

import pytest

from roster.shifts import still_on_shift


def test_equal_tokyo_instant_is_not_still_on_shift() -> None:
    now = datetime(2026, 1, 16, 0, 0, tzinfo=ZoneInfo("UTC"))
    shift_end = datetime(2026, 1, 16, 9, 0, tzinfo=ZoneInfo("Asia/Tokyo"))
    assert still_on_shift(now, shift_end) is False


def test_after_a_tokyo_close_is_not_still_on_shift() -> None:
    now = datetime(2026, 1, 16, 1, 0, tzinfo=ZoneInfo("UTC"))
    shift_end = datetime(2026, 1, 16, 9, 0, tzinfo=ZoneInfo("Asia/Tokyo"))
    assert still_on_shift(now, shift_end) is False


def test_naive_clock_is_rejected() -> None:
    with pytest.raises(ValueError):
        still_on_shift(
            datetime(2026, 1, 15, 12, 0),
            datetime(2026, 1, 15, 17, 0, tzinfo=ZoneInfo("UTC")),
        )
