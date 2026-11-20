from __future__ import annotations

from desk.tags import tag_ticket


def test_three_default_calls_stay_separate() -> None:
    assert tag_ticket("t1", "rush")["tags"] == ["rush"]
    assert tag_ticket("t2", "hold")["tags"] == ["hold"]
    assert tag_ticket("t3", "hem")["tags"] == ["hem"]


def test_a_supplied_list_does_not_become_the_next_default() -> None:
    tag_ticket("t1", "rush", ["cut"])
    assert tag_ticket("t2", "hold")["tags"] == ["hold"]
