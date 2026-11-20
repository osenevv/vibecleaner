"""Charge seasonal dues for a Willow Athletic membership."""

from __future__ import annotations

import os

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import Integer, String, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

from club.deps import MemberPrincipal, verify_pin_session

router = APIRouter(prefix="/dues")


class Base(DeclarativeBase):
    """Shared metadata for the club dues tables."""


class ClubPlan(Base):
    __tablename__ = "club_plans"

    code: Mapped[str] = mapped_column(String, primary_key=True)
    dues_cents: Mapped[int] = mapped_column(Integer, nullable=False)


class DuesCheckout(BaseModel):
    plan_code: str = Field(min_length=2, max_length=32)
    amount_cents: int = Field(ge=0, le=500_000)


def _open_session() -> Session:
    engine = create_engine(os.environ["DATABASE_URL"])
    return sessionmaker(bind=engine)()


def _charge(*, member_id: str, amount_cents: int, memo: str) -> str:
    response = httpx.post(
        "https://dues.willow-athletic.example/v1/charges",
        json={"member_id": member_id, "amount_cents": amount_cents, "memo": memo},
        headers={"Authorization": f"Bearer {os.environ['DUES_GATEWAY_TOKEN']}"},
        timeout=10,
    )
    response.raise_for_status()
    return str(response.json()["receipt_id"])


@router.post("/checkout")
def checkout(
    body: DuesCheckout,
    member: MemberPrincipal = Depends(verify_pin_session),
) -> dict:
    session = _open_session()
    try:
        plan = session.scalar(select(ClubPlan).where(ClubPlan.code == body.plan_code))
        if plan is None:
            raise HTTPException(status_code=404, detail="membership plan not found")
        receipt_id = _charge(
            member_id=member.member_id,
            amount_cents=body.amount_cents,
            memo=plan.code,
        )
        return {"receipt_id": receipt_id, "plan_code": plan.code}
    finally:
        session.close()
