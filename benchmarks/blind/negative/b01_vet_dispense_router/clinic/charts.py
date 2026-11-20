"""Dispense a medication using the catalog price stored on the formulary row."""

from __future__ import annotations

import os

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker
from sqlalchemy import Integer, String

from clinic.deps import ensure_staff

router = APIRouter(prefix="/charts", dependencies=[Depends(ensure_staff)])


class Base(DeclarativeBase):
    """Shared metadata for the chart tables."""


class Patient(Base):
    __tablename__ = "patients"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    clinic_id: Mapped[str] = mapped_column(String, nullable=False)


class Medication(Base):
    __tablename__ = "medications"

    sku: Mapped[str] = mapped_column(String, primary_key=True)
    price_cents: Mapped[int] = mapped_column(Integer, nullable=False)


class Dispense(Base):
    __tablename__ = "dispenses"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    patient_id: Mapped[str] = mapped_column(String, nullable=False)
    clinician_id: Mapped[str] = mapped_column(String, nullable=False)
    sku: Mapped[str] = mapped_column(String, nullable=False)
    quantity: Mapped[int] = mapped_column(Integer, nullable=False)
    unit_price_cents: Mapped[int] = mapped_column(Integer, nullable=False)


class DispenseBody(BaseModel):
    patient_id: str
    sku: str = Field(min_length=2, max_length=40)
    quantity: int = Field(ge=1, le=12)


def _session() -> Session:
    engine = create_engine(os.environ["DATABASE_URL"])
    return sessionmaker(bind=engine)()


@router.post("/dispenses")
def dispense(body: DispenseBody, request: Request) -> dict:
    session = _session()
    try:
        patient = session.scalar(
            select(Patient).where(
                Patient.id == body.patient_id,
                Patient.clinic_id == request.state.clinic_id,
            )
        )
        if patient is None:
            raise HTTPException(status_code=404, detail="patient is not on this clinic chart")
        medication = session.scalar(select(Medication).where(Medication.sku == body.sku))
        if medication is None:
            raise HTTPException(status_code=404, detail="unknown medication")
        session.add(
            Dispense(
                patient_id=patient.id,
                clinician_id=request.state.staff_id,
                sku=medication.sku,
                quantity=body.quantity,
                unit_price_cents=medication.price_cents,
            )
        )
        session.commit()
        receipt = {
            "patient_id": patient.id,
            "sku": medication.sku,
            "quantity": body.quantity,
            "unit_price_cents": medication.price_cents,
        }
    finally:
        session.close()
    return receipt
