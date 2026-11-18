from __future__ import annotations

import pytest

from delivery.attempts import deliver


def test_second_attempt_returns_the_send_result() -> None:
    state = {"calls": 0}

    def send(payload: dict[str, str]) -> dict[str, object]:
        state["calls"] += 1
        if state["calls"] == 1:
            raise TimeoutError("slow")
        return {"ok": True, "id": payload["id"], "attempt": state["calls"]}

    assert deliver(send, {"id": "job-1"}) == {"ok": True, "id": "job-1", "attempt": 2}


def test_value_error_is_not_turned_into_success() -> None:
    def send(_payload: dict[str, str]) -> dict[str, object]:
        raise ValueError("bad payload")

    with pytest.raises(ValueError):
        deliver(send, {"id": "job-1"})


def test_one_attempt_timeout_raises() -> None:
    def send(_payload: dict[str, str]) -> dict[str, object]:
        raise TimeoutError("slow")

    with pytest.raises(TimeoutError):
        deliver(send, {"id": "job-1"}, attempts=1)
