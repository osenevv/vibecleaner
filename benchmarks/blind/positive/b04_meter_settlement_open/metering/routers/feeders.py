"""Read recent feeder intervals. Auth is attached on this router only."""

from __future__ import annotations

import os

import psycopg
from fastapi import APIRouter, Depends

from metering.deps import StaffPrincipal, ensure_staff

router = APIRouter(prefix="/feeders", dependencies=[Depends(ensure_staff)])


@router.get("/intervals")
def list_intervals(staff: StaffPrincipal = Depends(ensure_staff)) -> dict:
    with psycopg.connect(os.environ["DATABASE_URL"]) as conn:
        rows = conn.execute(
            """
            select feeder_code, hour_start, kilowatt_hours
            from feeder_intervals
            where cooperative_id = %s
            order by hour_start desc
            limit 24
            """,
            (staff.cooperative_id,),
        ).fetchall()
    return {
        "cooperative_id": staff.cooperative_id,
        "intervals": [
            {"feeder_code": code, "hour_start": start.isoformat(), "kilowatt_hours": kwh}
            for code, start, kwh in rows
        ],
    }
