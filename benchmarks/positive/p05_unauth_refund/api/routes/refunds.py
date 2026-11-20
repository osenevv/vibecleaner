"""Refund creation for the storefront API."""

from __future__ import annotations

import os
from dataclasses import dataclass

import psycopg
from fastapi import APIRouter, FastAPI, HTTPException
from pydantic import BaseModel, Field

app = FastAPI(title="Refunds")
router = APIRouter()


def connection():
    return psycopg.connect(os.environ["DATABASE_URL"])


@dataclass(frozen=True)
class Order:
    id: str
    total_cents: int


class RefundIn(BaseModel):
    order_id: str = Field(min_length=1)
    reason: str = Field(min_length=1, max_length=500)


class RefundOut(BaseModel):
    refund_id: str
    amount_cents: int


def fetch_order(order_id: str) -> Order | None:
    with connection() as conn:
        row = conn.execute(
            "SELECT id, total_cents FROM orders WHERE id = %s LIMIT 1",
            (order_id,),
        ).fetchone()
    if row is None:
        return None
    return Order(id=str(row[0]), total_cents=int(row[1]))


def insert_refund(order_id: str, amount_cents: int, reason: str) -> str:
    with connection() as conn:
        row = conn.execute(
            """
            INSERT INTO refunds (order_id, amount_cents, reason)
            VALUES (%s, %s, %s)
            RETURNING id
            """,
            (order_id, amount_cents, reason),
        ).fetchone()
        conn.commit()
    return str(row[0])


@router.post("/refunds", response_model=RefundOut)
def create_refund(body: RefundIn) -> RefundOut:
    order = fetch_order(body.order_id)
    if order is None:
        raise HTTPException(status_code=404, detail="order not found")
    refund_id = insert_refund(order.id, order.total_cents, body.reason)
    return RefundOut(refund_id=refund_id, amount_cents=order.total_cents)


app.include_router(router)
