from __future__ import annotations

from weight import grams


def test_one_pound() -> None:
    assert grams(1) == 454
