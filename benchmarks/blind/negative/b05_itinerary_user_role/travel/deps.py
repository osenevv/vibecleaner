"""Traveler session for fare-rule explanations."""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import HTTPException, Request


@dataclass(frozen=True)
class TravelerPrincipal:
    traveler_id: str


def assert_signed_in(request: Request) -> TravelerPrincipal:
    token = request.cookies.get("traveler_session")
    if not token or "." not in token:
        raise HTTPException(status_code=401, detail="traveler sign-in required")
    traveler_id = token.split(".", 1)[0]
    if not traveler_id:
        raise HTTPException(status_code=401, detail="traveler session rejected")
    return TravelerPrincipal(traveler_id=traveler_id)
