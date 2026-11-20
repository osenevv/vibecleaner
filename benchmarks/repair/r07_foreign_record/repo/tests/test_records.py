from __future__ import annotations

import pytest

from auth.records import read_body


def test_other_actor_cannot_read() -> None:
    records = {"r1": {"owner": "ada", "body": "north dock"}}
    with pytest.raises(PermissionError):
        read_body(records, "grace", "r1")


def test_valid_input_owner_reads() -> None:
    records = {"r1": {"owner": "ada", "body": "north dock"}}
    assert read_body(records, "ada", "r1") == "north dock"
