from __future__ import annotations

import pytest

from auth.records import read_body


def test_each_record_stays_with_its_owner() -> None:
    records = {
        "r1": {"owner": "ada", "body": "north dock"},
        "r2": {"owner": "grace", "body": "south dock"},
    }
    with pytest.raises(PermissionError):
        read_body(records, "ada", "r2")
    assert read_body(records, "grace", "r2") == "south dock"


def test_missing_record_raises_key_error() -> None:
    with pytest.raises(KeyError):
        read_body({}, "ada", "r9")
