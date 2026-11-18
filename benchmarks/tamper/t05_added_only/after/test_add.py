from __future__ import annotations

from add import add


def test_adds_two_quantities() -> None:
    assert add(1, 1) == 2
