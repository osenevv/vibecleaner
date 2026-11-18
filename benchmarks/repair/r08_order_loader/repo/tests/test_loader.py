from __future__ import annotations

from packing.loader import OrderBook, load_customer_orders


def book() -> OrderBook:
    orders = [
        {"id": "o1", "customer_id": "ada", "line_ids": ["l1", "l2"]},
        {"id": "o2", "customer_id": "ada", "line_ids": ["l3"]},
        {"id": "o3", "customer_id": "mina", "line_ids": ["l4"]},
    ]
    lines = {
        "o1": [
            {"id": "l1", "sku": "bolt", "qty": 2},
            {"id": "l2", "sku": "nut", "qty": 4},
        ],
        "o2": [{"id": "l3", "sku": "washer", "qty": 1}],
        "o3": [{"id": "l4", "sku": "pin", "qty": 8}],
    }
    return OrderBook(orders, lines)


def test_two_orders_use_two_queries() -> None:
    orders = book()
    loaded = load_customer_orders(orders, "ada")
    assert [row["id"] for row in loaded] == ["o1", "o2"]
    assert orders.queries == 2


def test_valid_input_unknown_customer_is_empty() -> None:
    orders = book()
    assert load_customer_orders(orders, "no-one") == []
    assert orders.queries == 1
