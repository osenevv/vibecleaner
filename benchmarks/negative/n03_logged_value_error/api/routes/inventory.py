"""Inventory adjustments. Bad quantities are logged and rejected."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass

import psycopg
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

logger = logging.getLogger("inventory")
app = FastAPI(title="Inventory")


@dataclass(frozen=True)
class User:
    id: str


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


class AdjustIn(BaseModel):
    sku: str = Field(min_length=1, max_length=40)
    quantity_raw: str = Field(min_length=1, max_length=12)


class AdjustOut(BaseModel):
    sku: str
    quantity: int


def parse_quantity(raw: str) -> int:
    try:
        quantity = int(raw)
    except ValueError:
        logger.warning("rejected non-integer quantity %r", raw)
        raise HTTPException(status_code=400, detail="quantity must be an integer") from None
    if quantity < 1 or quantity > 1000:
        raise HTTPException(status_code=400, detail="quantity out of range")
    return quantity


@router.post("/inventory/adjust", response_model=AdjustOut)
def adjust(body: AdjustIn, request: Request) -> AdjustOut:
    user: User = request.state.user
    quantity = parse_quantity(body.quantity_raw)
    with connection() as conn:
        conn.execute(
            """
            INSERT INTO inventory_moves (user_id, sku, quantity)
            VALUES (%s, %s, %s)
            """,
            (user.id, body.sku, quantity),
        )
        conn.commit()
    return AdjustOut(sku=body.sku, quantity=quantity)


app.include_router(router)
