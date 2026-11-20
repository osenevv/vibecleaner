"""Counsel session for the Harbor & Pine review desk."""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import HTTPException, Request


@dataclass(frozen=True)
class CounselPrincipal:
    counsel_id: str
    firm_id: str


def assert_signed_in(request: Request) -> CounselPrincipal:
    token = request.cookies.get("counsel_session")
    if not token or token.count(".") != 1:
        raise HTTPException(status_code=401, detail="counsel sign-in required")
    counsel_id, firm_id = token.split(".", 1)
    if not counsel_id or not firm_id:
        raise HTTPException(status_code=401, detail="counsel session rejected")
    return CounselPrincipal(counsel_id=counsel_id, firm_id=firm_id)
