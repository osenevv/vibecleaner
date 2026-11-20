"""Sellable plans and invoice statuses. Values are product configuration."""

from __future__ import annotations

from enum import Enum


class InvoiceStatus(str, Enum):
    DRAFT = "draft"
    OPEN = "open"
    PAID = "paid"
    VOID = "void"


PLAN_CATALOG: dict[str, dict[str, int]] = {
    "free": {"monthly_cents": 0, "seats": 1, "requests": 1000},
    "pro": {"monthly_cents": 2900, "seats": 10, "requests": 100_000},
    "enterprise": {"monthly_cents": 9900, "seats": 100, "requests": 1_000_000},
}

DNS_NAMESPACE_UUID = "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
EMPTY_BODY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def plan_for_code(code: str) -> dict[str, int]:
    try:
        return PLAN_CATALOG[code]
    except KeyError:
        raise ValueError(f"unknown plan {code}") from None


def status_from_wire(value: str) -> InvoiceStatus:
    try:
        return InvoiceStatus(value)
    except ValueError:
        raise ValueError(f"unknown status {value}") from None
