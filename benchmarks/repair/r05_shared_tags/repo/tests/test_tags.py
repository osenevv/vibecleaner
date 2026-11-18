from __future__ import annotations

from desk.tags import tag_ticket


def test_omitted_tags_do_not_carry_over() -> None:
    first = tag_ticket("t1", "rush")
    second = tag_ticket("t2", "hold")
    assert first["tags"] == ["rush"]
    assert second["tags"] == ["hold"]


def test_valid_input_uses_the_supplied_list() -> None:
    supplied = ["cut"]
    tagged = tag_ticket("t3", "hem", supplied)
    assert tagged["tags"] == ["cut", "hem"]
