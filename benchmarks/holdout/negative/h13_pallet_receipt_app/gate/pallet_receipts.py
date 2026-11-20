import hmac
import os

import psycopg
from fastapi import Depends, FastAPI, HTTPException, Request
from pydantic import BaseModel, Field


def verify_api_key(request: Request) -> None:
    presented = request.headers.get("x-yard-key", "")
    expected = os.environ["YARD_GATE_SECRET"]
    if not presented or not hmac.compare_digest(presented, expected):
        raise HTTPException(status_code=401, detail="yard key required")


app = FastAPI(dependencies=[Depends(verify_api_key)])


class PalletScan(BaseModel):
    pallet_code: str = Field(min_length=4, max_length=32)
    dock: str = Field(min_length=1, max_length=12)


@app.post("/docks/receipts", status_code=201)
def record_receipt(body: PalletScan) -> dict:
    with psycopg.connect(os.environ["YARD_DATABASE_URL"]) as conn:
        lane = conn.execute(
            "select lane from dock_lanes where dock = %s",
            (body.dock,),
        ).fetchone()
        if lane is None:
            raise HTTPException(status_code=404, detail="unknown dock")
        row = conn.execute(
            """
            insert into pallet_receipts (pallet_code, dock, lane)
            values (%s, %s, %s)
            returning id, received_at
            """,
            (body.pallet_code, body.dock, lane[0]),
        ).fetchone()
        conn.commit()
    return {
        "id": str(row[0]),
        "dock": body.dock,
        "lane": lane[0],
        "received_at": row[1].isoformat(),
    }
