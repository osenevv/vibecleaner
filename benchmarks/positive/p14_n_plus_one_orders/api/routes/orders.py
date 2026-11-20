"""Order inbox. Each order loads its buyer with a separate query."""

from __future__ import annotations

import os
from dataclasses import dataclass

import psycopg
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request
from pydantic import BaseModel

app = FastAPI(title="Orders")


@dataclass(frozen=True)
class User:
    id: str


@dataclass(frozen=True)
class OrderRow:
    id: str
    buyer_id: str
    total_cents: int


class OrderView(BaseModel):
    id: str
    total_cents: int
    buyer_email: str


def connection():
    return psycopg.connect(os.environ["DATABASE_URL"])


def get_current_user(request: Request) -> User:
    header = request.headers.get("authorization", "")
    if not header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="unauthorized")
    token = header.removeprefix("Bearer ").strip()
    with connection() as conn:
        row = conn.execute(
            "SELECT user_id FROM sessions WHERE token = %s LIMIT 1",
            (token,),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=401, detail="unauthorized")
    user = User(id=str(row[0]))
    request.state.user = user
    return user


router = APIRouter(dependencies=[Depends(get_current_user)])


def fetch_orders(owner_id: str) -> list[OrderRow]:
    with connection() as conn:
        rows = conn.execute(
            """
            SELECT id, buyer_id, total_cents
            FROM orders
            WHERE owner_id = %s
            ORDER BY created_at DESC
            LIMIT 50
            """,
            (owner_id,),
        ).fetchall()
    return [
        OrderRow(id=str(row[0]), buyer_id=str(row[1]), total_cents=int(row[2]))
        for row in rows
    ]


@router.get("/orders/enriched", response_model=list[OrderView])
def enriched_orders(request: Request) -> list[OrderView]:
    user: User = request.state.user
    orders = fetch_orders(user.id)
    views: list[OrderView] = []
    for order in orders:
        with connection() as conn:
            buyer = conn.execute(
                "SELECT email FROM buyers WHERE id = %s LIMIT 1",
                (order.buyer_id,),
            ).fetchone()
        email = "" if buyer is None else str(buyer[0])
        views.append(OrderView(id=order.id, total_cents=order.total_cents, buyer_email=email))
    return views


app.include_router(router)
