from __future__ import annotations

from turnstile.hits import HitCounter


def test_reentered_hit_counts() -> None:
    counter = HitCounter()
    state = {"used": False}

    def callback(current: HitCounter) -> None:
        if state["used"]:
            return
        state["used"] = True
        current.hit()

    counter.listen(callback)
    counter.hit()
    assert counter.total == 2


def test_valid_input_counts_two_separate_hits() -> None:
    counter = HitCounter()
    counter.hit()
    counter.hit()
    assert counter.total == 2
