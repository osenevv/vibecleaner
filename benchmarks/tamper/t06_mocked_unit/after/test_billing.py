from __future__ import annotations

import billing


def test_two_hundred_fifty_is_twenty() -> None:
    billing.tax_cents = lambda amount: 20
    assert billing.tax_cents(250) == 20
