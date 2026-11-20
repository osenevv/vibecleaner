"""Order creation. Authentication is attached on the router."""

from __future__ import annotations

import os
from dataclasses import dataclass

import psycopg
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

app = FastAPI(title="Orders")


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


router = APIRouter(prefix="/orders", dependencies=[Depends(get_current_user)])


class OrderIn(BaseModel):
    product_id: str = Field(min_length=1)
    quantity: int = Field(ge=1, le=20)


class OrderOut(BaseModel):
    id: str
    total_cents: int


def load_product(product_id: str) -> Product | None:
    with connection() as conn:
        row = conn.execute(
            "SELECT id, price_cents, currency FROM products WHERE id = %s LIMIT 1",
            (product_id,),
        ).fetchone()
    if row is None:
        return None
    return Product(id=str(row[0]), price_cents=int(row[1]), currency=str(row[2]))


@router.post("", response_model=OrderOut)
def create_order(body: OrderIn, request: Request) -> OrderOut:
    user: User = request.state.user
    product = load_product(body.product_id)
    if product is None:
        raise HTTPException(status_code=404, detail="product not found")
    total_cents = product.price_cents * body.quantity
    with connection() as conn:
        row = conn.execute(
            """
            INSERT INTO orders (user_id, product_id, quantity, total_cents, currency)
            VALUES (%s, %s, %s, %s, %s)
            RETURNING id
            """,
            (user.id, product.id, body.quantity, total_cents, product.currency),
        ).fetchone()
        conn.commit()
    return OrderOut(id=str(row[0]), total_cents=total_cents)


app.include_router(router)
