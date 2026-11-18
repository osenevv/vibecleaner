from __future__ import annotations

from collections.abc import Callable


class HitCounter:
    def __init__(self) -> None:
        self.total = 0
        self._listeners: list[Callable[[HitCounter], None]] = []

    def listen(self, callback: Callable[[HitCounter], None]) -> None:
        self._listeners.append(callback)

    def hit(self) -> None:
        seen = self.total
        for callback in list(self._listeners):
            callback(self)
        self.total = seen + 1
