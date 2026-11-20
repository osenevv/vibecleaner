from __future__ import annotations

from port import read_port


def test_documented_port() -> None:
    assert read_port("8080") == 8080
