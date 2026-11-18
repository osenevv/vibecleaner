"""People-ops session for the Northwind hire desk."""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import HTTPException, Request


@dataclass(frozen=True)
class StaffPrincipal:
    person_id: str
    office_id: str


def ensure_staff(request: Request) -> StaffPrincipal:
    token = request.cookies.get("people_ops_session")
    if not token or token.count(".") != 1:
        raise HTTPException(status_code=401, detail="people-ops sign-in required")
    person_id, office_id = token.split(".", 1)
    if not person_id or not office_id:
        raise HTTPException(status_code=401, detail="people-ops session rejected")
    return StaffPrincipal(person_id=person_id, office_id=office_id)
