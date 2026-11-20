"""Capture a pledge for the amount stored on the pledge row."""

from __future__ import annotations

import logging
import os

import httpx
import psycopg
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from donations.deps import StaffPrincipal, ensure_staff

router = APIRouter(prefix="/pledges")
logger = logging.getLogger("kiln.pledges")


class GatewayTimeout(Exception):
    """The donation processor did not answer before the desk timeout."""


class PledgeCapture(BaseModel):
    pledge_id: str = Field(min_length=1, max_length=64)


def _capture(gateway_ref: str, amount_cents: int) -> str:
    try:
        response = httpx.post(
            "https://pay.kiln-kettle.example/v1/captures",
            json={"gateway_ref": gateway_ref, "amount_cents": amount_cents},
            headers={"Authorization": f"Bearer {os.environ['PLEDGE_GATEWAY_TOKEN']}"},
            timeout=8,
        )
    except httpx.TimeoutException as exc:
        raise GatewayTimeout(str(exc)) from exc
    response.raise_for_status()
    return str(response.json()["receipt_id"])


@router.post("/capture")
def capture(
    body: PledgeCapture,
    clerk: StaffPrincipal = Depends(ensure_staff),
) -> dict:
    with psycopg.connect(os.environ["DATABASE_URL"]) as conn:
        row = conn.execute(
            """
            select gateway_ref, amount_cents
            from pledges
            where id = %s
            """,
            (body.pledge_id,),
        ).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="pledge not found")
        gateway_ref, amount_cents = row
        try:
            receipt_id = _capture(gateway_ref, int(amount_cents))
        except GatewayTimeout as exc:
            logger.exception("pledge capture timed out", extra={"pledge_id": body.pledge_id})
            raise HTTPException(status_code=502, detail="gateway timeout") from exc
        conn.execute(
            """
            insert into pledge_receipts (pledge_id, clerk_id, receipt_id)
            values (%s, %s, %s)
            """,
            (body.pledge_id, clerk.clerk_id, receipt_id),
        )
    return {"receipt_id": receipt_id}
