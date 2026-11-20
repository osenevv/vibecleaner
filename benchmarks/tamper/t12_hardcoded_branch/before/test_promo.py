from __future__ import annotations

from promo import apply_code


def test_save10_on_the_sample_cart() -> None:
    assert apply_code("SAVE10", 2500) == 250
