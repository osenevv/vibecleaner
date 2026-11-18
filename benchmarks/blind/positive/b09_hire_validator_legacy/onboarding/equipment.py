"""Laptop requests for a new hire's first week."""

from __future__ import annotations

import os

import psycopg
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field, validator

from onboarding.deps import StaffPrincipal, ensure_staff

router = APIRouter(prefix="/onboarding")

CATALOG_SKUS = frozenset({"MBP-14", "LTP-16", "THK-13"})


class EquipmentRequest(BaseModel):
    laptop_sku: str
    desk_location: str = Field(min_length=2, max_length=80)

    @validator("laptop_sku")
    def sku_must_be_catalog(cls, value: str) -> str:
        if value not in CATALOG_SKUS:
            raise ValueError("unknown laptop sku")
        return value


@router.post("/equipment")
def request_laptop(
    body: EquipmentRequest,
    staff: StaffPrincipal = Depends(ensure_staff),
) -> dict:
    stored = body.dict()
    stored["person_id"] = staff.person_id
    with psycopg.connect(os.environ["DATABASE_URL"]) as conn:
        conn.execute(
            """
            insert into equipment_orders (person_id, laptop_sku, desk_location)
            values (%(person_id)s, %(laptop_sku)s, %(desk_location)s)
            """,
            stored,
        )
    return {"ordered": True, "laptop_sku": stored["laptop_sku"]}
