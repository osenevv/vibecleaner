from __future__ import annotations

import pytest

from tax import tax_cents


def test_eight_percent_rounds_half_up() -> None:
    assert tax_cents(100) == 8


def test_negative_amount_is_rejected() -> None:
    with pytest.raises(ValueError):
        tax_cents(-1)
