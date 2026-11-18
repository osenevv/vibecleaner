"""Checkout charges the catalog price for the requested product."""

from __future__ import annotations

import os
from dataclasses import dataclass

import psycopg
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

app = FastAPI(title="Checkout")


@dataclass(frozen=True)
class User:
    id: str


@dataclass(frozen=True)
class Product:
    id: str
    price_cents: int
    currency: str


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


class CheckoutIn(BaseModel):
    product_id: str = Field(min_length=1)
    quantity: int = Field(ge=1, le=20)
    amount_cents: int | None = None


class Receipt(BaseModel):
    charge_id: str
    amount_cents: int
    currency: str


def require_product(product_id: str) -> Product:
    with connection() as conn:
        row = conn.execute(
            "SELECT id, price_cents, currency FROM products WHERE id = %s LIMIT 1",
            (product_id,),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="product not found")
    return Product(id=str(row[0]), price_cents=int(row[1]), currency=str(row[2]))


def charge(user_id: str, amount_cents: int, currency: str, product_id: str) -> str:
    with connection() as conn:
        row = conn.execute(
            """
            INSERT INTO charges (user_id, amount_cents, currency, product_id)
            VALUES (%s, %s, %s, %s)
            RETURNING id
            """,
            (user_id, amount_cents, currency, product_id),
        ).fetchone()
        conn.commit()
    return str(row[0])


@router.post("/checkout", response_model=Receipt)
def checkout(body: CheckoutIn, user: User = Depends(get_current_user)) -> Receipt:
    product = require_product(body.product_id)
    total = product.price_cents * body.quantity
    charge_id = charge(user.id, total, product.currency, product.id)
    return Receipt(charge_id=charge_id, amount_cents=total, currency=product.currency)


app.include_router(router)
