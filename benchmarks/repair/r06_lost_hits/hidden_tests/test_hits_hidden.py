from __future__ import annotations

from turnstile.hits import HitCounter


def test_two_reentered_hits_count() -> None:
    counter = HitCounter()
    state = {"left": 2}

    def callback(current: HitCounter) -> None:
        if state["left"] <= 0:
            return
        state["left"] -= 1
        current.hit()

    counter.listen(callback)
    counter.hit()
    assert counter.total == 3


def test_listener_sees_the_counted_hit() -> None:
    counter = HitCounter()
    seen: list[int] = []
    counter.listen(lambda current: seen.append(current.total))
    counter.hit()
    assert counter.total == 1
    assert seen == [1]
