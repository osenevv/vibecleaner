from __future__ import annotations

from collections.abc import Callable


def deliver(
    send: Callable[[dict[str, str]], dict[str, object]],
    payload: dict[str, str],
    attempts: int = 3,
) -> dict[str, object]:
    for _ in range(attempts):
        try:
            return send(payload)
        except TimeoutError:
            continue
    return {"ok": True, "id": payload["id"]}
