"""Chart-desk session. Attached on the router, not repeated per handler."""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import HTTPException, Request


@dataclass(frozen=True)
class StaffPrincipal:
    staff_id: str
    clinic_id: str


def ensure_staff(request: Request) -> StaffPrincipal:
    token = request.cookies.get("staff_session")
    if not token or token.count(".") != 1:
        raise HTTPException(status_code=401, detail="staff sign-in required")
    staff_id, clinic_id = token.split(".", 1)
    if not staff_id or not clinic_id:
        raise HTTPException(status_code=401, detail="staff session rejected")
    principal = StaffPrincipal(staff_id=staff_id, clinic_id=clinic_id)
    request.state.staff_id = principal.staff_id
    request.state.clinic_id = principal.clinic_id
    return principal
