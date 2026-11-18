"""Clerk session for the Kiln & Kettle pledge desk."""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import HTTPException, Request


@dataclass(frozen=True)
class StaffPrincipal:
    clerk_id: str


def ensure_staff(request: Request) -> StaffPrincipal:
    token = request.cookies.get("clerk_session")
    if not token or "." not in token:
        raise HTTPException(status_code=401, detail="clerk sign-in required")
    clerk_id = token.split(".", 1)[0]
    if not clerk_id:
        raise HTTPException(status_code=401, detail="clerk session rejected")
    return StaffPrincipal(clerk_id=clerk_id)
