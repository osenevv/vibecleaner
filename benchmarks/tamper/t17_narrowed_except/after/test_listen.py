from __future__ import annotations

import pytest

from listen import parse_port


def test_documented_port() -> None:
    assert parse_port("8080") == 8080


def test_word_is_rejected() -> None:
    with pytest.raises(ValueError):
        parse_port("nope")
