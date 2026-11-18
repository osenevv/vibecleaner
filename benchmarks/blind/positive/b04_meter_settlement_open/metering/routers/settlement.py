"""Submit a feeder window to the GridSettle partner API."""

from __future__ import annotations

import os
from datetime import datetime

import httpx
import psycopg
from fastapi import APIRouter
from pydantic import BaseModel, Field

router = APIRouter(prefix="/settlements")


class SettlementWindow(BaseModel):
    feeder_code: str = Field(min_length=2, max_length=16)
    hour_start: datetime


@router.post("/windows")
def submit_window(body: SettlementWindow) -> dict:
    # GridSettle invoices the cooperative per accepted feeder window.
    response = httpx.post(
        "https://api.gridsettle.example/v1/feeder-windows",
        headers={"Authorization": f"Bearer {os.environ['GRIDSETTLE_TOKEN']}"},
        json={
            "feeder_code": body.feeder_code,
            "hour_start": body.hour_start.isoformat(),
        },
        timeout=10,
    )
    response.raise_for_status()
    confirmation_id = str(response.json()["confirmation_id"])
    with psycopg.connect(os.environ["DATABASE_URL"]) as conn:
        conn.execute(
            """
            insert into feeder_settlements (feeder_code, hour_start, confirmation_id)
            values (%s, %s, %s)
            """,
            (body.feeder_code, body.hour_start, confirmation_id),
        )
    return {"confirmation_id": confirmation_id}
