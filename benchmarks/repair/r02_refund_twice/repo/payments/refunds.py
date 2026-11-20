from __future__ import annotations


def refund(charges: dict[str, dict[str, int]], charge_id: str, amount: int) -> int:
    charge = charges[charge_id]
    captured = charge["captured"]
    if amount < 1 or amount > captured:
        raise ValueError("refund is outside the captured amount")
    charge["refunded"] = charge["refunded"] + amount
    return charge["refunded"]
