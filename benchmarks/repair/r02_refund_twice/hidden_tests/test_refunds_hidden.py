from __future__ import annotations

import pytest

from payments.refunds import refund


def test_remainder_after_a_partial_refund_is_accepted() -> None:
    charges = {"c1": {"captured": 1000, "refunded": 0}}
    refund(charges, "c1", 400)
    assert refund(charges, "c1", 600) == 1000


def test_partial_past_the_remainder_is_refused() -> None:
    charges = {"c1": {"captured": 1000, "refunded": 0}}
    refund(charges, "c1", 700)
    with pytest.raises(ValueError):
        refund(charges, "c1", 400)


def test_zero_amount_is_refused() -> None:
    charges = {"c1": {"captured": 1000, "refunded": 0}}
    with pytest.raises(ValueError):
        refund(charges, "c1", 0)


def test_unknown_charge_raises_key_error() -> None:
    with pytest.raises(KeyError):
        refund({}, "c9", 100)
