"""Staff session for feeder-interval reads."""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import HTTPException, Request


@dataclass(frozen=True)
class StaffPrincipal:
    staff_id: str
    cooperative_id: str


def ensure_staff(request: Request) -> StaffPrincipal:
    token = request.cookies.get("meter_staff")
    if not token or token.count(".") != 1:
        raise HTTPException(status_code=401, detail="meter staff sign-in required")
    staff_id, cooperative_id = token.split(".", 1)
    if not staff_id or not cooperative_id:
        raise HTTPException(status_code=401, detail="meter staff session rejected")
    return StaffPrincipal(staff_id=staff_id, cooperative_id=cooperative_id)
