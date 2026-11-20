from __future__ import annotations


class OrderBook:
    def __init__(
        self,
        orders: list[dict[str, object]],
        lines: dict[str, list[dict[str, object]]],
    ) -> None:
        self._orders = orders
        self._lines = lines
        self.queries = 0

    def order_ids(self, customer_id: str) -> list[str]:
        self.queries += 1
        return [str(row["id"]) for row in self._orders if row["customer_id"] == customer_id]

    def order(self, order_id: str) -> dict[str, object]:
        self.queries += 1
        for row in self._orders:
            if row["id"] == order_id:
                return {
                    "id": row["id"],
                    "customer_id": row["customer_id"],
                    "line_ids": list(row["line_ids"]),
                }
        raise KeyError(order_id)

    def line(self, line_id: str) -> dict[str, object]:
        self.queries += 1
        for grouped in self._lines.values():
            for item in grouped:
                if item["id"] == line_id:
                    return dict(item)
        raise KeyError(line_id)

    def orders_for(self, customer_id: str) -> list[dict[str, object]]:
        self.queries += 1
        return [
            {
                "id": row["id"],
                "customer_id": row["customer_id"],
                "line_ids": list(row["line_ids"]),
            }
            for row in self._orders
            if row["customer_id"] == customer_id
        ]

    def lines_for(self, order_ids: list[str]) -> dict[str, list[dict[str, object]]]:
        self.queries += 1
        return {order_id: [dict(item) for item in self._lines.get(order_id, [])] for order_id in order_ids}


def load_customer_orders(book: OrderBook, customer_id: str) -> list[dict[str, object]]:
    loaded: list[dict[str, object]] = []
    for order_id in book.order_ids(customer_id):
        order = book.order(order_id)
        order["lines"] = [book.line(str(line_id)) for line_id in order["line_ids"]]
        loaded.append(order)
    return loaded
