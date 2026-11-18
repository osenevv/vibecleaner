from __future__ import annotations

import pytest

from delivery.attempts import deliver


def test_exhausted_attempts_raise() -> None:
    def send(_payload: dict[str, str]) -> dict[str, object]:
        raise TimeoutError("slow")

    with pytest.raises(TimeoutError):
        deliver(send, {"id": "job-1"})


def test_valid_input_returns_the_first_success() -> None:
    def send(payload: dict[str, str]) -> dict[str, object]:
        return {"ok": True, "id": payload["id"]}

    assert deliver(send, {"id": "job-1"}) == {"ok": True, "id": "job-1"}
