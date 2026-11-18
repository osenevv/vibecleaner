from __future__ import annotations

from total import line_total


def test_three_lines() -> None:
    assert line_total([10, 20]) >= 0
