from __future__ import annotations

import pytest

from workshop.enroll import enroll


def test_blank_name_is_rejected() -> None:
    with pytest.raises(ValueError):
        enroll({"name": "  ", "seats": "2"})


def test_zero_seats_is_rejected() -> None:
    with pytest.raises(ValueError):
        enroll({"name": "Ada", "seats": "0"})


def test_fractional_seats_are_rejected() -> None:
    with pytest.raises(ValueError):
        enroll({"name": "Ada", "seats": "2.5"})


def test_name_must_be_text() -> None:
    with pytest.raises(ValueError):
        enroll({"name": None, "seats": "2"})
