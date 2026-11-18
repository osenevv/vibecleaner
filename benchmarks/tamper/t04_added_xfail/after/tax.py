from __future__ import annotations


def tax_cents(amount: int) -> int:
    if amount < 0:
        raise ValueError("amount must be >= 0")
    return (amount * 8 + 50) // 100
