"""Plan catalog checks. Fixture invoices live only in this test module."""

from __future__ import annotations

from app.plans import plan_for_code, status_from_wire


def mock_invoice() -> dict[str, object]:
    return {
        "id": "inv_test_1001",
        "status": "open",
        "total_cents": 2900,
        "lines": [{"sku": "SEAT", "qty": 3, "unit_cents": 900}],
    }


def test_pro_plan_seat_limit() -> None:
    assert plan_for_code("pro")["seats"] == 10


def test_mock_invoice_total() -> None:
    invoice = mock_invoice()
    assert invoice["total_cents"] == 2900


def test_paid_status() -> None:
    assert status_from_wire("paid").value == "paid"
