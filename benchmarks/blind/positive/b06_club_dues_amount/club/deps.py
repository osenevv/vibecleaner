"""Pin-session gate for the Willow Athletic clubhouse API."""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import HTTPException, Request


@dataclass(frozen=True)
class MemberPrincipal:
    member_id: str
    club_id: str


def verify_pin_session(request: Request) -> MemberPrincipal:
    token = request.cookies.get("club_pin_session")
    if not token or token.count(".") != 1:
        raise HTTPException(status_code=401, detail="club pin session required")
    member_id, club_id = token.split(".", 1)
    if not member_id or not club_id:
        raise HTTPException(status_code=401, detail="club pin session rejected")
    return MemberPrincipal(member_id=member_id, club_id=club_id)
