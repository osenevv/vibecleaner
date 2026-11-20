"""Queue a meter export for the signed-in tenant account."""

from __future__ import annotations

import os

import psycopg
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from metering.deps import TenantPrincipal, requireTenant

router = APIRouter(prefix="/intervals", dependencies=[Depends(requireTenant)])


class IntervalExport(BaseModel):
    user_id: str = Field(min_length=1, max_length=64)
    meter_id: str = Field(min_length=1, max_length=64)


@router.post("/exports")
def export_intervals(
    body: IntervalExport,
    principal: TenantPrincipal = Depends(requireTenant),
) -> dict:
    if body.user_id != principal.user_id:
        raise HTTPException(status_code=403, detail="session does not match user_id")
    with psycopg.connect(os.environ["DATABASE_URL"]) as conn:
        meter = conn.execute(
            "select id from meters where id = %s and tenant_id = %s",
            (body.meter_id, principal.tenant_id),
        ).fetchone()
        if meter is None:
            raise HTTPException(status_code=404, detail="meter is not on this tenant")
        conn.execute(
            """
            insert into interval_exports (tenant_id, meter_id, requested_by)
            values (%s, %s, %s)
            """,
            (principal.tenant_id, body.meter_id, principal.user_id),
        )
    return {"queued": True, "meter_id": body.meter_id}
