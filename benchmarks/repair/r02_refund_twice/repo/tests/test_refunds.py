from __future__ import annotations

import pytest

from payments.refunds import refund


def test_second_full_refund_is_refused() -> None:
    charges = {"c1": {"captured": 1000, "refunded": 0}}
    refund(charges, "c1", 1000)
    with pytest.raises(ValueError):
        refund(charges, "c1", 1000)


def test_valid_input_first_partial_refund() -> None:
    charges = {"c1": {"captured": 1000, "refunded": 0}}
    assert refund(charges, "c1", 400) == 400
