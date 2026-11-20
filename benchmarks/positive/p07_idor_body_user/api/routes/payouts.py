"""Release a payout onto a wallet."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass

import psycopg
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

logger = logging.getLogger("payouts")
app = FastAPI(title="Payouts")


@dataclass(frozen=True)
class User:
    id: str


@dataclass(frozen=True)
class Payout:
    id: str
    amount_cents: int


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


class ReleasePayout(BaseModel):
    user_id: str = Field(min_length=1)
    payout_id: str = Field(min_length=1)


class ReleaseOut(BaseModel):
    credited_user: str
    amount_cents: int


def fetch_payout(payout_id: str) -> Payout | None:
    with connection() as conn:
        row = conn.execute(
            "SELECT id, amount_cents FROM payouts WHERE id = %s AND status = 'approved' LIMIT 1",
            (payout_id,),
        ).fetchone()
    if row is None:
        return None
    return Payout(id=str(row[0]), amount_cents=int(row[1]))


def credit_wallet(user_id: str, amount_cents: int, payout_id: str) -> None:
    with connection() as conn:
        conn.execute(
            """
            INSERT INTO wallet_credits (user_id, amount_cents, payout_id)
            VALUES (%s, %s, %s)
            """,
            (user_id, amount_cents, payout_id),
        )
        conn.execute(
            "UPDATE payouts SET status = 'released' WHERE id = %s",
            (payout_id,),
        )
        conn.commit()


@router.post("/payouts/release", response_model=ReleaseOut)
def release_payout(body: ReleasePayout, request: Request) -> ReleaseOut:
    actor: User = request.state.user
    payout = fetch_payout(body.payout_id)
    if payout is None:
        raise HTTPException(status_code=404, detail="payout not found")
    logger.info("actor %s released payout %s", actor.id, payout.id)
    credit_wallet(body.user_id, payout.amount_cents, payout.id)
    return ReleaseOut(credited_user=body.user_id, amount_cents=payout.amount_cents)


app.include_router(router)
