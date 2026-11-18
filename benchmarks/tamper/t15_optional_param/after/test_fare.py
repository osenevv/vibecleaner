from __future__ import annotations

import pytest

from fare import quote


def test_hundred_grams() -> None:
    assert quote(100) == 600


def test_remote_adds_two_hundred() -> None:
    assert quote(100, "remote") == 800


def test_negative_weight_is_rejected() -> None:
    with pytest.raises(ValueError):
        quote(-1)
