from __future__ import annotations

import pytest

from catalog.pages import page_rows


def test_second_page_is_the_next_window() -> None:
    rows = ["bolt", "nut", "washer", "screw"]
    assert page_rows(rows, 2, 2) == ["washer", "screw"]


def test_third_page_of_five_is_the_last_row() -> None:
    rows = ["bolt", "nut", "washer", "screw", "pin"]
    assert page_rows(rows, 3, 2) == ["pin"]


def test_page_past_the_end_is_empty() -> None:
    assert page_rows(["bolt", "nut"], 4, 2) == []


def test_size_below_one_is_rejected() -> None:
    with pytest.raises(ValueError):
        page_rows(["bolt"], 1, 0)
