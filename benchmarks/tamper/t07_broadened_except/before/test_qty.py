from __future__ import annotations

import pytest

from qty import parse_qty


def test_digits() -> None:
    assert parse_qty("3") == 3


def test_word_is_rejected() -> None:
    with pytest.raises(ValueError):
        parse_qty("nope")
