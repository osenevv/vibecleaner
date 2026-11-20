from __future__ import annotations

from packing.loader import OrderBook, load_customer_orders


def test_eight_orders_still_use_two_queries() -> None:
    orders = [
        {"id": f"o{index}", "customer_id": "ada", "line_ids": [f"l{index}"]}
        for index in range(8)
    ]
    lines = {f"o{index}": [{"id": f"l{index}", "sku": f"sku-{index}", "qty": index + 1}] for index in range(8)}
    book = OrderBook(orders, lines)
    loaded = load_customer_orders(book, "ada")
    assert [row["lines"][0]["sku"] for row in loaded] == [f"sku-{index}" for index in range(8)]
    assert book.queries == 2


def test_unknown_customer_does_not_query_lines() -> None:
    book = OrderBook([], {})
    assert load_customer_orders(book, "ada") == []
    assert book.queries == 1
