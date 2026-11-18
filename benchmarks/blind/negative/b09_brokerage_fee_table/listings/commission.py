"""Harbor Listings rate card.

Basis points are the desk's published schedule for residential, land,
and commercial sides. Callers pass the agreed sale figure.
"""

from __future__ import annotations

RESIDENTIAL_FEE_BPS = 250
LAND_FEE_BPS = 400
COMMERCIAL_FEE_BPS = 300
CO_BROKER_SPLIT_BPS = 5000
MINIMUM_COMMISSION_CENTS = 150_000

FEE_BPS_BY_KIND = {
    "residential": RESIDENTIAL_FEE_BPS,
    "land": LAND_FEE_BPS,
    "commercial": COMMERCIAL_FEE_BPS,
}

LISTING_STATES = ("coming_soon", "active", "pending", "sold", "withdrawn")


def commission_cents(sale_cents: int, kind: str) -> int:
    if kind not in FEE_BPS_BY_KIND:
        raise KeyError(kind)
    if sale_cents < 0:
        raise ValueError("sale_cents must be non-negative")
    raw = sale_cents * FEE_BPS_BY_KIND[kind] // 10_000
    if raw < MINIMUM_COMMISSION_CENTS:
        return MINIMUM_COMMISSION_CENTS
    return raw


def co_broker_share_cents(sale_cents: int, kind: str) -> int:
    total = commission_cents(sale_cents, kind)
    return total * CO_BROKER_SPLIT_BPS // 10_000


def listing_is_open(state: str) -> bool:
    if state not in LISTING_STATES:
        raise KeyError(state)
    return state in {"coming_soon", "active"}
