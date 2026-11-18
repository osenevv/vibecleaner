from __future__ import annotations


def parse_qty(raw: str) -> int:
    try:
        qty = int(raw)
    except ValueError:
        raise ValueError("quantity must be a whole number") from None
    if qty < 1:
        raise ValueError("quantity must be at least 1")
    return qty
