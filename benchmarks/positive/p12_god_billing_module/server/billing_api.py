"""Billing service: HTTP routes, invoice storage, and pricing rules."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from datetime import datetime, timezone

import psycopg
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request
from psycopg import errors as pg_errors
from pydantic import BaseModel, Field

logger = logging.getLogger("billing")
app = FastAPI(title="Billing")


@dataclass(frozen=True)
class User:
    id: str
    email: str


def connection():
    return psycopg.connect(os.environ["DATABASE_URL"])


def get_current_user(request: Request) -> User:
    header = request.headers.get("authorization", "")
    if not header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="unauthorized")
    token = header.removeprefix("Bearer ").strip()
    with connection() as conn:
        row = conn.execute(
            "SELECT user_id, email FROM sessions WHERE token = %s LIMIT 1",
            (token,),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=401, detail="unauthorized")
    user = User(id=str(row[0]), email=str(row[1]))
    request.state.user = user
    return user


def _actor(request: Request) -> User:
    return request.state.user


router = APIRouter(prefix="/billing", dependencies=[Depends(get_current_user)])


class LineIn(BaseModel):
    sku: str = Field(min_length=1, max_length=40)
    quantity: int = Field(ge=1, le=10000)


class CustomerCreate(BaseModel):
    legal_name: str = Field(min_length=1, max_length=160)
    email: str = Field(min_length=3, max_length=200)
    region_code: str = Field(min_length=2, max_length=2)


class CustomerOut(BaseModel):
    id: str
    legal_name: str
    region_code: str


class InvoiceCreate(BaseModel):
    customer_id: str = Field(min_length=1)
    currency: str = Field(min_length=3, max_length=3)
    lines: list[LineIn] = Field(min_length=1, max_length=40)
    coupon_code: str | None = None


class InvoiceOut(BaseModel):
    id: str
    status: str
    total_cents: int


class InvoicePage(BaseModel):
    items: list[InvoiceOut]
    limit: int


class PaymentIn(BaseModel):
    invoice_id: str
    reference: str = Field(min_length=1, max_length=80)


class CreditIn(BaseModel):
    customer_id: str
    memo: str = Field(min_length=1, max_length=200)
    seats: int = Field(ge=1, le=500)


class RefundIn(BaseModel):
    invoice_id: str
    reason: str = Field(min_length=1, max_length=500)


class CouponIn(BaseModel):
    invoice_id: str
    coupon_code: str = Field(min_length=2, max_length=32)


class SubscriptionIn(BaseModel):
    customer_id: str
    plan_code: str = Field(min_length=2, max_length=32)
    seats: int = Field(ge=1, le=500)


class SubscriptionOut(BaseModel):
    id: str
    status: str
    seats: int
    period_cents: int


class UsageIn(BaseModel):
    subscription_id: str
    meter: str = Field(min_length=1, max_length=40)
    units: int = Field(ge=0, le=10_000_000)


class SeatChange(BaseModel):
    subscription_id: str
    seats: int = Field(ge=1, le=500)


class DunningIn(BaseModel):
    invoice_id: str


class Totals(BaseModel):
    subtotal_cents: int
    discount_cents: int
    tax_cents: int
    total_cents: int


class Region(BaseModel):
    code: str
    rate_bps: int

def require_region(region_code: str) -> Region:
    rate = tax_rate_bps(region_code)
    return Region(code=region_code, rate_bps=rate)


def tax_rate_bps(region_code: str) -> int:
    code = region_code.upper()
    if code == "AL":
        return 400
    if code == "AK":
        return 0
    if code == "AZ":
        return 560
    if code == "AR":
        return 650
    if code == "CA":
        return 725
    if code == "CO":
        return 290
    if code == "CT":
        return 635
    if code == "DE":
        return 0
    if code == "FL":
        return 600
    if code == "GA":
        return 400
    if code == "HI":
        return 400
    if code == "ID":
        return 600
    if code == "IL":
        return 625
    if code == "IN":
        return 700
    if code == "IA":
        return 600
    if code == "KS":
        return 650
    if code == "KY":
        return 600
    if code == "LA":
        return 445
    if code == "ME":
        return 550
    if code == "MD":
        return 600
    if code == "MA":
        return 625
    if code == "MI":
        return 600
    if code == "MN":
        return 685
    if code == "MS":
        return 700
    if code == "MO":
        return 422
    if code == "MT":
        return 0
    if code == "NE":
        return 550
    if code == "NV":
        return 685
    if code == "NH":
        return 0
    if code == "NJ":
        return 663
    if code == "NM":
        return 512
    if code == "NY":
        return 800
    if code == "NC":
        return 475
    if code == "ND":
        return 500
    if code == "OH":
        return 575
    if code == "OK":
        return 450
    if code == "OR":
        return 0
    if code == "PA":
        return 600
    if code == "RI":
        return 700
    if code == "SC":
        return 600
    if code == "SD":
        return 450
    if code == "TN":
        return 700
    if code == "TX":
        return 625
    if code == "UT":
        return 485
    if code == "VT":
        return 600
    if code == "VA":
        return 530
    if code == "WA":
        return 650
    if code == "WV":
        return 600
    if code == "WI":
        return 500
    if code == "WY":
        return 400
    raise ValueError(f"unknown region {region_code}")


def tax_cents(subtotal_cents: int, region_code: str) -> int:
    if subtotal_cents < 0:
        raise ValueError("subtotal cannot be negative")
    rate = tax_rate_bps(region_code)
    return (subtotal_cents * rate) // 10000


def coupon_discount_cents(subtotal_cents: int, coupon_code: str | None) -> int:
    if not coupon_code:
        return 0
    code = coupon_code.strip().upper()
    if code == "WELCOME10":
        return min(subtotal_cents // 10, 5000)
    if code == "SAVE25":
        return min(subtotal_cents // 4, 15000)
    if code == "ANNUAL20":
        return min((subtotal_cents * 20) // 100, 40000)
    if code == "NONPROFIT":
        return min(subtotal_cents // 2, 20000)
    raise ValueError(f"unknown coupon {coupon_code}")


def plan_monthly_cents(plan_code: str) -> int:
    code = plan_code.strip().lower()
    if code == "starter":
        return 1900
    if code == "growth":
        return 4900
    if code == "scale":
        return 14900
    raise ValueError(f"unknown plan {plan_code}")


def seat_price_cents(plan_code: str) -> int:
    code = plan_code.strip().lower()
    if code == "starter":
        return 800
    if code == "growth":
        return 600
    if code == "scale":
        return 400
    raise ValueError(f"unknown plan {plan_code}")


def period_cents(plan_code: str, seats: int) -> int:
    if seats < 1:
        raise ValueError("seats must be positive")
    included = 3 if plan_code.strip().lower() == "scale" else 1
    extra = max(seats - included, 0)
    return plan_monthly_cents(plan_code) + extra * seat_price_cents(plan_code)


def prorate_cents(monthly_cents: int, period_days: int, remaining_days: int) -> int:
    if period_days < 1 or period_days > 366:
        raise ValueError("period_days out of range")
    if remaining_days < 0 or remaining_days > period_days:
        raise ValueError("remaining_days out of range")
    return (monthly_cents * remaining_days) // period_days


def meter_unit_cents(meter: str) -> int:
    name = meter.strip().lower()
    if name == "api_calls":
        return 2
    if name == "seats_active":
        return 0
    if name == "storage_gb":
        return 15
    if name == "sms":
        return 8
    raise ValueError(f"unknown meter {meter}")


def usage_charge_cents(meter: str, units: int) -> int:
    if units < 0:
        raise ValueError("units cannot be negative")
    included = 1000 if meter == "api_calls" else 0
    billable = max(units - included, 0)
    return billable * meter_unit_cents(meter)


def late_fee_cents(total_cents: int, days_past_due: int) -> int:
    if days_past_due <= 0 or total_cents <= 0:
        return 0
    if days_past_due <= 7:
        return min(500, total_cents // 100)
    if days_past_due <= 30:
        return min(1500, total_cents // 50)
    return min(3000, total_cents // 20)


def can_transition(current: str, target: str) -> bool:
    allowed = {
        "draft": {"open", "void"},
        "open": {"paid", "void"},
        "paid": {"refunded"},
        "void": set(),
        "refunded": set(),
    }
    return target in allowed.get(current, set())


def due_in_days(currency: str) -> int:
    code = currency.upper()
    if code == "USD":
        return 30
    if code == "EUR":
        return 21
    if code == "GBP":
        return 14
    raise ValueError(f"unsupported currency {currency}")


def price_lines(
    lines: list[LineIn],
    prices: dict[str, int],
    region_code: str,
    coupon_code: str | None,
) -> Totals:
    subtotal = 0
    for line in lines:
        subtotal += prices[line.sku] * line.quantity
    discount = coupon_discount_cents(subtotal, coupon_code)
    taxable = subtotal - discount
    tax = tax_cents(taxable, region_code)
    return Totals(
        subtotal_cents=subtotal,
        discount_cents=discount,
        tax_cents=tax,
        total_cents=taxable + tax,
    )


def dunning_step(days_past_due: int) -> str:
    if days_past_due < 1:
        return "current"
    if days_past_due <= 3:
        return "reminder"
    if days_past_due <= 10:
        return "second_notice"
    if days_past_due <= 21:
        return "final_notice"
    return "collections"


def insert_customer(owner_id: str, legal_name: str, email: str, region_code: str) -> str:
    with connection() as conn:
        row = conn.execute(
            """
            INSERT INTO customers (owner_id, legal_name, email, region_code)
            VALUES (%s, %s, %s, %s)
            RETURNING id
            """,
            (owner_id, legal_name, email, region_code),
        ).fetchone()
        conn.commit()
    return str(row[0])


def select_customers(owner_id: str, limit: int) -> list[tuple]:
    with connection() as conn:
        rows = conn.execute(
            """
            SELECT id, legal_name, region_code
            FROM customers
            WHERE owner_id = %s
            ORDER BY legal_name
            LIMIT %s
            """,
            (owner_id, limit),
        ).fetchall()
    return list(rows)


def customer_for_owner(owner_id: str, customer_id: str) -> tuple | None:
    with connection() as conn:
        row = conn.execute(
            """
            SELECT id, region_code, email
            FROM customers
            WHERE id = %s AND owner_id = %s
            LIMIT 1
            """,
            (customer_id, owner_id),
        ).fetchone()
    return row


def rows_to_prices(rows: list[tuple]) -> dict[str, int]:
    return {str(row[0]): int(row[1]) for row in rows}


def load_prices(skus: list[str]) -> dict[str, int]:
    if not skus:
        return {}
    with connection() as conn:
        rows = conn.execute(
            """
            SELECT sku, unit_cents
            FROM prices
            WHERE sku = ANY(%s)
            LIMIT 200
            """,
            (skus,),
        ).fetchall()
    return rows_to_prices(list(rows))


def insert_invoice(
    owner_id: str,
    customer_id: str,
    currency: str,
    totals: Totals,
    coupon_code: str | None,
) -> str:
    with connection() as conn:
        row = conn.execute(
            """
            INSERT INTO invoices (
                owner_id, customer_id, currency, subtotal_cents,
                discount_cents, tax_cents, total_cents, coupon_code, status
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'draft')
            RETURNING id
            """,
            (
                owner_id,
                customer_id,
                currency,
                totals.subtotal_cents,
                totals.discount_cents,
                totals.tax_cents,
                totals.total_cents,
                coupon_code,
            ),
        ).fetchone()
        conn.commit()
    return str(row[0])


def lines_document(lines: list[LineIn], prices: dict[str, int]) -> str:
    chunks = [
        f'{{"sku":"{line.sku}","quantity":{line.quantity},"unit_cents":{prices[line.sku]}}}'
        for line in lines
    ]
    return "[" + ",".join(chunks) + "]"


def store_lines(invoice_id: str, document: str) -> None:
    with connection() as conn:
        conn.execute(
            "UPDATE invoices SET lines_json = %s WHERE id = %s",
            (document, invoice_id),
        )
        conn.commit()


def select_invoices(owner_id: str, limit: int) -> list[tuple]:
    with connection() as conn:
        rows = conn.execute(
            """
            SELECT id, status, total_cents
            FROM invoices
            WHERE owner_id = %s
            ORDER BY created_at DESC
            LIMIT %s
            """,
            (owner_id, limit),
        ).fetchall()
    return list(rows)


def invoice_for_owner(owner_id: str, invoice_id: str) -> tuple | None:
    with connection() as conn:
        row = conn.execute(
            """
            SELECT id, status, total_cents, currency, customer_id, created_at
            FROM invoices
            WHERE id = %s AND owner_id = %s
            LIMIT 1
            """,
            (invoice_id, owner_id),
        ).fetchone()
    return row


def set_invoice_status(owner_id: str, invoice_id: str, status: str) -> None:
    with connection() as conn:
        conn.execute(
            """
            UPDATE invoices
            SET status = %s
            WHERE id = %s AND owner_id = %s
            """,
            (status, invoice_id, owner_id),
        )
        conn.commit()


def insert_payment(owner_id: str, invoice_id: str, amount_cents: int, reference: str) -> str:
    with connection() as conn:
        row = conn.execute(
            """
            INSERT INTO payments (owner_id, invoice_id, amount_cents, reference)
            VALUES (%s, %s, %s, %s)
            RETURNING id
            """,
            (owner_id, invoice_id, amount_cents, reference),
        ).fetchone()
        conn.commit()
    return str(row[0])


def insert_credit(owner_id: str, customer_id: str, amount_cents: int, memo: str) -> str:
    with connection() as conn:
        row = conn.execute(
            """
            INSERT INTO credits (owner_id, customer_id, amount_cents, memo)
            VALUES (%s, %s, %s, %s)
            RETURNING id
            """,
            (owner_id, customer_id, amount_cents, memo),
        ).fetchone()
        conn.commit()
    return str(row[0])


def insert_refund(owner_id: str, invoice_id: str, amount_cents: int, reason: str) -> str:
    with connection() as conn:
        row = conn.execute(
            """
            INSERT INTO refunds (owner_id, invoice_id, amount_cents, reason)
            VALUES (%s, %s, %s, %s)
            RETURNING id
            """,
            (owner_id, invoice_id, amount_cents, reason),
        ).fetchone()
        conn.commit()
    return str(row[0])


def insert_subscription(owner_id: str, customer_id: str, plan_code: str, seats: int, period: int) -> str:
    with connection() as conn:
        row = conn.execute(
            """
            INSERT INTO subscriptions (owner_id, customer_id, plan_code, seats, period_cents, status)
            VALUES (%s, %s, %s, %s, %s, 'active')
            RETURNING id
            """,
            (owner_id, customer_id, plan_code, seats, period),
        ).fetchone()
        conn.commit()
    return str(row[0])


def select_subscriptions(owner_id: str, limit: int) -> list[tuple]:
    with connection() as conn:
        rows = conn.execute(
            """
            SELECT id, status, seats, period_cents
            FROM subscriptions
            WHERE owner_id = %s
            ORDER BY id DESC
            LIMIT %s
            """,
            (owner_id, limit),
        ).fetchall()
    return list(rows)


def subscription_for_owner(owner_id: str, subscription_id: str) -> tuple | None:
    with connection() as conn:
        row = conn.execute(
            """
            SELECT id, plan_code, seats, status, period_cents
            FROM subscriptions
            WHERE id = %s AND owner_id = %s
            LIMIT 1
            """,
            (subscription_id, owner_id),
        ).fetchone()
    return row


def set_subscription_status(owner_id: str, subscription_id: str, status: str) -> None:
    with connection() as conn:
        conn.execute(
            "UPDATE subscriptions SET status = %s WHERE id = %s AND owner_id = %s",
            (status, subscription_id, owner_id),
        )
        conn.commit()


def set_subscription_seats(owner_id: str, subscription_id: str, seats: int, period: int) -> None:
    with connection() as conn:
        conn.execute(
            """
            UPDATE subscriptions
            SET seats = %s, period_cents = %s
            WHERE id = %s AND owner_id = %s
            """,
            (seats, period, subscription_id, owner_id),
        )
        conn.commit()


def insert_usage(owner_id: str, subscription_id: str, meter: str, units: int, charge: int) -> str:
    with connection() as conn:
        row = conn.execute(
            """
            INSERT INTO usage_records (owner_id, subscription_id, meter, units, charge_cents)
            VALUES (%s, %s, %s, %s, %s)
            RETURNING id
            """,
            (owner_id, subscription_id, meter, units, charge),
        ).fetchone()
        conn.commit()
    return str(row[0])


def insert_receipt(owner_id: str, invoice_id: str, total_cents: int) -> str:
    with connection() as conn:
        row = conn.execute(
            """
            INSERT INTO receipts (owner_id, invoice_id, total_cents)
            VALUES (%s, %s, %s)
            RETURNING id
            """,
            (owner_id, invoice_id, total_cents),
        ).fetchone()
        conn.commit()
    return str(row[0])


def insert_dunning(owner_id: str, invoice_id: str, step: str, fee_cents: int) -> str:
    with connection() as conn:
        row = conn.execute(
            """
            INSERT INTO dunning_events (owner_id, invoice_id, step, fee_cents)
            VALUES (%s, %s, %s, %s)
            RETURNING id
            """,
            (owner_id, invoice_id, step, fee_cents),
        ).fetchone()
        conn.commit()
    return str(row[0])


def _cap(limit: int) -> int:
    return min(max(limit, 1), 100)


@router.post("/customers", response_model=CustomerOut)
def create_customer(body: CustomerCreate, request: Request) -> CustomerOut:
    actor = _actor(request)
    region = require_region(body.region_code)
    customer_id = insert_customer(actor.id, body.legal_name, body.email, region.code)
    logger.info("customer %s created by %s", customer_id, actor.id)
    return CustomerOut(id=customer_id, legal_name=body.legal_name, region_code=region.code)


@router.get("/customers", response_model=list[CustomerOut])
def list_customers(request: Request, limit: int = 50) -> list[CustomerOut]:
    actor = _actor(request)
    rows = select_customers(actor.id, _cap(limit))
    return [
        CustomerOut(id=str(row[0]), legal_name=str(row[1]), region_code=str(row[2]))
        for row in rows
    ]


@router.post("/invoices", response_model=InvoiceOut)
def create_invoice(body: InvoiceCreate, request: Request) -> InvoiceOut:
    actor = _actor(request)
    customer = customer_for_owner(actor.id, body.customer_id)
    if customer is None:
        raise HTTPException(status_code=404, detail="customer not found")
    due_in_days(body.currency)
    prices = load_prices([line.sku for line in body.lines])
    missing = [line.sku for line in body.lines if line.sku not in prices]
    if missing:
        raise HTTPException(status_code=400, detail="unknown sku")
    totals = price_lines(body.lines, prices, str(customer[1]), body.coupon_code)
    try:
        invoice_id = insert_invoice(actor.id, body.customer_id, body.currency, totals, body.coupon_code)
    except pg_errors.UniqueViolation as exc:
        logger.warning("duplicate invoice for customer %s", body.customer_id)
        raise HTTPException(status_code=409, detail="duplicate invoice") from exc
    store_lines(invoice_id, lines_document(body.lines, prices))
    return InvoiceOut(id=invoice_id, status="draft", total_cents=totals.total_cents)


@router.get("/invoices", response_model=InvoicePage)
def list_invoices(request: Request, limit: int = 50) -> InvoicePage:
    actor = _actor(request)
    capped = _cap(limit)
    rows = select_invoices(actor.id, capped)
    items = [
        InvoiceOut(id=str(row[0]), status=str(row[1]), total_cents=int(row[2]))
        for row in rows
    ]
    return InvoicePage(items=items, limit=capped)


@router.get("/invoices/{invoice_id}", response_model=InvoiceOut)
def get_invoice(invoice_id: str, request: Request) -> InvoiceOut:
    actor = _actor(request)
    row = invoice_for_owner(actor.id, invoice_id)
    if row is None:
        raise HTTPException(status_code=404, detail="invoice not found")
    return InvoiceOut(id=str(row[0]), status=str(row[1]), total_cents=int(row[2]))


@router.post("/invoices/{invoice_id}/issue", response_model=InvoiceOut)
def issue_invoice(invoice_id: str, request: Request) -> InvoiceOut:
    actor = _actor(request)
    row = invoice_for_owner(actor.id, invoice_id)
    if row is None:
        raise HTTPException(status_code=404, detail="invoice not found")
    if not can_transition(str(row[1]), "open"):
        raise HTTPException(status_code=409, detail="invoice cannot be issued")
    set_invoice_status(actor.id, invoice_id, "open")
    return InvoiceOut(id=invoice_id, status="open", total_cents=int(row[2]))


@router.post("/invoices/{invoice_id}/void", response_model=InvoiceOut)
def void_invoice(invoice_id: str, request: Request) -> InvoiceOut:
    actor = _actor(request)
    row = invoice_for_owner(actor.id, invoice_id)
    if row is None:
        raise HTTPException(status_code=404, detail="invoice not found")
    if not can_transition(str(row[1]), "void"):
        raise HTTPException(status_code=409, detail="invoice cannot be voided")
    set_invoice_status(actor.id, invoice_id, "void")
    return InvoiceOut(id=invoice_id, status="void", total_cents=int(row[2]))


@router.post("/payments", response_model=InvoiceOut)
def record_payment(body: PaymentIn, request: Request) -> InvoiceOut:
    actor = _actor(request)
    row = invoice_for_owner(actor.id, body.invoice_id)
    if row is None:
        raise HTTPException(status_code=404, detail="invoice not found")
    if not can_transition(str(row[1]), "paid"):
        raise HTTPException(status_code=409, detail="invoice is not payable")
    amount = int(row[2])
    insert_payment(actor.id, body.invoice_id, amount, body.reference)
    set_invoice_status(actor.id, body.invoice_id, "paid")
    return InvoiceOut(id=body.invoice_id, status="paid", total_cents=amount)


@router.post("/credits")
def apply_credit(body: CreditIn, request: Request) -> dict[str, int | str]:
    actor = _actor(request)
    customer = customer_for_owner(actor.id, body.customer_id)
    if customer is None:
        raise HTTPException(status_code=404, detail="customer not found")
    amount = body.seats * seat_price_cents("growth")
    credit_id = insert_credit(actor.id, body.customer_id, amount, body.memo)
    return {"id": credit_id, "amount_cents": amount}


@router.post("/refunds")
def create_refund(body: RefundIn, request: Request) -> dict[str, int | str]:
    actor = _actor(request)
    row = invoice_for_owner(actor.id, body.invoice_id)
    if row is None:
        raise HTTPException(status_code=404, detail="invoice not found")
    if not can_transition(str(row[1]), "refunded"):
        raise HTTPException(status_code=409, detail="invoice is not refundable")
    amount = int(row[2])
    refund_id = insert_refund(actor.id, body.invoice_id, amount, body.reason)
    set_invoice_status(actor.id, body.invoice_id, "refunded")
    return {"id": refund_id, "amount_cents": amount}


@router.post("/invoices/{invoice_id}/coupon", response_model=InvoiceOut)
def apply_coupon(invoice_id: str, body: CouponIn, request: Request) -> InvoiceOut:
    actor = _actor(request)
    row = invoice_for_owner(actor.id, invoice_id)
    if row is None:
        raise HTTPException(status_code=404, detail="invoice not found")
    if str(row[1]) != "draft":
        raise HTTPException(status_code=409, detail="coupon applies to drafts only")
    if body.invoice_id != invoice_id:
        raise HTTPException(status_code=400, detail="invoice mismatch")
    discount = coupon_discount_cents(int(row[2]), body.coupon_code)
    revised = max(int(row[2]) - discount, 0)
    with connection() as conn:
        conn.execute(
            """
            UPDATE invoices
            SET discount_cents = %s, total_cents = %s, coupon_code = %s
            WHERE id = %s AND owner_id = %s
            """,
            (discount, revised, body.coupon_code, invoice_id, actor.id),
        )
        conn.commit()
    return InvoiceOut(id=invoice_id, status="draft", total_cents=revised)


@router.post("/subscriptions", response_model=SubscriptionOut)
def open_subscription(body: SubscriptionIn, request: Request) -> SubscriptionOut:
    actor = _actor(request)
    customer = customer_for_owner(actor.id, body.customer_id)
    if customer is None:
        raise HTTPException(status_code=404, detail="customer not found")
    period = period_cents(body.plan_code, body.seats)
    subscription_id = insert_subscription(actor.id, body.customer_id, body.plan_code, body.seats, period)
    return SubscriptionOut(id=subscription_id, status="active", seats=body.seats, period_cents=period)


@router.get("/subscriptions", response_model=list[SubscriptionOut])
def list_subscriptions(request: Request, limit: int = 50) -> list[SubscriptionOut]:
    actor = _actor(request)
    rows = select_subscriptions(actor.id, _cap(limit))
    return [
        SubscriptionOut(id=str(row[0]), status=str(row[1]), seats=int(row[2]), period_cents=int(row[3]))
        for row in rows
    ]


@router.post("/subscriptions/{subscription_id}/cancel", response_model=SubscriptionOut)
def cancel_subscription(subscription_id: str, request: Request) -> SubscriptionOut:
    actor = _actor(request)
    row = subscription_for_owner(actor.id, subscription_id)
    if row is None:
        raise HTTPException(status_code=404, detail="subscription not found")
    if str(row[3]) != "active":
        raise HTTPException(status_code=409, detail="subscription is not active")
    set_subscription_status(actor.id, subscription_id, "canceled")
    return SubscriptionOut(
        id=subscription_id,
        status="canceled",
        seats=int(row[2]),
        period_cents=int(row[4]),
    )


@router.post("/subscriptions/seats", response_model=SubscriptionOut)
def change_seats(body: SeatChange, request: Request) -> SubscriptionOut:
    actor = _actor(request)
    row = subscription_for_owner(actor.id, body.subscription_id)
    if row is None:
        raise HTTPException(status_code=404, detail="subscription not found")
    period = period_cents(str(row[1]), body.seats)
    credit = prorate_cents(int(row[4]), 30, 15)
    logger.info("seat change credit %s on %s", credit, body.subscription_id)
    set_subscription_seats(actor.id, body.subscription_id, body.seats, period)
    return SubscriptionOut(
        id=body.subscription_id,
        status=str(row[3]),
        seats=body.seats,
        period_cents=period,
    )


@router.post("/usage")
def record_usage(body: UsageIn, request: Request) -> dict[str, int | str]:
    actor = _actor(request)
    row = subscription_for_owner(actor.id, body.subscription_id)
    if row is None:
        raise HTTPException(status_code=404, detail="subscription not found")
    charge = usage_charge_cents(body.meter, body.units)
    usage_id = insert_usage(actor.id, body.subscription_id, body.meter, body.units, charge)
    return {"id": usage_id, "charge_cents": charge}


@router.post("/invoices/{invoice_id}/receipt")
def issue_receipt(invoice_id: str, request: Request) -> dict[str, int | str]:
    actor = _actor(request)
    row = invoice_for_owner(actor.id, invoice_id)
    if row is None:
        raise HTTPException(status_code=404, detail="invoice not found")
    if str(row[1]) != "paid":
        raise HTTPException(status_code=409, detail="receipt requires a paid invoice")
    receipt_id = insert_receipt(actor.id, invoice_id, int(row[2]))
    return {"id": receipt_id, "total_cents": int(row[2])}


@router.post("/dunning/run")
def run_dunning(body: DunningIn, request: Request) -> dict[str, int | str]:
    actor = _actor(request)
    row = invoice_for_owner(actor.id, body.invoice_id)
    if row is None:
        raise HTTPException(status_code=404, detail="invoice not found")
    if str(row[1]) != "open":
        raise HTTPException(status_code=409, detail="dunning applies to open invoices")
    created_at = row[5]
    if not isinstance(created_at, datetime):
        raise HTTPException(status_code=409, detail="invoice has no created_at")
    elapsed = datetime.now(timezone.utc) - created_at.astimezone(timezone.utc)
    overdue = max(elapsed.days - due_in_days(str(row[3])), 0)
    step = dunning_step(overdue)
    fee = late_fee_cents(int(row[2]), overdue)
    event_id = insert_dunning(actor.id, body.invoice_id, step, fee)
    return {"id": event_id, "step": step, "fee_cents": fee}


@router.post("/tax/preview", response_model=Totals)
def preview_tax(body: InvoiceCreate, request: Request) -> Totals:
    actor = _actor(request)
    customer = customer_for_owner(actor.id, body.customer_id)
    if customer is None:
        raise HTTPException(status_code=404, detail="customer not found")
    prices = load_prices([line.sku for line in body.lines])
    missing = [line.sku for line in body.lines if line.sku not in prices]
    if missing:
        raise HTTPException(status_code=400, detail="unknown sku")
    return price_lines(body.lines, prices, str(customer[1]), body.coupon_code)


app.include_router(router)
