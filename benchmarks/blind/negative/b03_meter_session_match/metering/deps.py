"""Tenant session for interval exports."""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import HTTPException, Request


@dataclass(frozen=True)
class TenantPrincipal:
    user_id: str
    tenant_id: str


def requireTenant(request: Request) -> TenantPrincipal:
    token = request.cookies.get("tenant_session")
    if not token or token.count(".") != 1:
        raise HTTPException(status_code=401, detail="tenant sign-in required")
    user_id, tenant_id = token.split(".", 1)
    if not user_id or not tenant_id:
        raise HTTPException(status_code=401, detail="tenant session rejected")
    return TenantPrincipal(user_id=user_id, tenant_id=tenant_id)
