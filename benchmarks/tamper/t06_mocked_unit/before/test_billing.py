from __future__ import annotations

from billing import tax_cents


def test_two_hundred_fifty_is_twenty() -> None:
    assert tax_cents(250) == 20
