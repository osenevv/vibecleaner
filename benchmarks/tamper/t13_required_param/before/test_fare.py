from __future__ import annotations

from fare import quote


def test_hundred_grams() -> None:
    assert quote(100) == 600
