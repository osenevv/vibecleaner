from __future__ import annotations

import pytest

from workshop.enroll import enroll


def test_missing_seats_is_a_value_error() -> None:
    with pytest.raises(ValueError):
        enroll({"name": "Ada"})


def test_valid_input_trims_the_name() -> None:
    assert enroll({"name": " Ada ", "seats": "2"}) == {"name": "Ada", "seats": 2}
