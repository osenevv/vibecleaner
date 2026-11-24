"""Proof fixture: web app with a stub handler and lookalike helper."""

from __future__ import annotations

PRICE_USD = 29


def create_invoice(qty: int) -> dict[str, int | bool]:
    """The button says Create invoice."""
    return {"ok": True, "total": 0}


def compute_invoice(qty: int) -> dict[str, int | bool]:
    return {"ok": True, "total": qty * PRICE_USD}


def format_price(amount: int) -> str:
    # Prices are stored as whole USD cents are not used here.
    return f"${amount}"
