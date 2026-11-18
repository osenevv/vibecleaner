from __future__ import annotations

import pytest

from catalog.pages import page_rows


def test_first_page_returns_a_full_window() -> None:
    rows = ["bolt", "nut", "washer", "screw"]
    assert page_rows(rows, 1, 2) == ["bolt", "nut"]


def test_valid_input_empty_list() -> None:
    assert page_rows([], 1, 2) == []


def test_page_below_one_is_rejected() -> None:
    with pytest.raises(ValueError):
        page_rows(["bolt"], 0, 2)
