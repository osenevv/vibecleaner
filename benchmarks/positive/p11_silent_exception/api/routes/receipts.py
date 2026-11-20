"""Receipt emails. Delivery failures are ignored so checkout still returns."""

from __future__ import annotations

import logging
import os
import smtplib
from dataclasses import dataclass
from email.message import EmailMessage

import psycopg
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

logger = logging.getLogger("receipts")
app = FastAPI(title="Receipts")


@dataclass(frozen=True)
class User:
    id: str
    email: str


def connection():
    return psycopg.connect(os.environ["DATABASE_URL"])


def get_current_user(request: Request) -> User:
    header = request.headers.get("authorization", "")
    if not header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="unauthorized")
    token = header.removeprefix("Bearer ").strip()
    with connection() as conn:
        row = conn.execute(
            "SELECT user_id, email FROM sessions WHERE token = %s LIMIT 1",
            (token,),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=401, detail="unauthorized")
    user = User(id=str(row[0]), email=str(row[1]))
    request.state.user = user
    return user


router = APIRouter(dependencies=[Depends(get_current_user)])


class ReceiptIn(BaseModel):
    order_id: str = Field(min_length=1)


class ReceiptOut(BaseModel):
    id: str


def insert_receipt(user_id: str, order_id: str) -> str:
    with connection() as conn:
        row = conn.execute(
            """
            INSERT INTO receipts (user_id, order_id)
            VALUES (%s, %s)
            RETURNING id
            """,
            (user_id, order_id),
        ).fetchone()
        conn.commit()
    return str(row[0])


def send_receipt_email(recipient: str, receipt_id: str) -> None:
    message = EmailMessage()
    message["From"] = os.environ["RECEIPTS_FROM"]
    message["To"] = recipient
    message["Subject"] = f"Receipt {receipt_id}"
    message.set_content(f"Your receipt {receipt_id} is ready.")
    with smtplib.SMTP(os.environ["SMTP_HOST"], int(os.environ.get("SMTP_PORT", "587"))) as smtp:
        smtp.send_message(message)


@router.post("/receipts", response_model=ReceiptOut)
def create_receipt(body: ReceiptIn, request: Request) -> ReceiptOut:
    user: User = request.state.user
    receipt_id = insert_receipt(user.id, body.order_id)
    try:
        send_receipt_email(user.email, receipt_id)
    except Exception:
        pass
    logger.info("receipt %s stored for %s", receipt_id, user.id)
    return ReceiptOut(id=receipt_id)


app.include_router(router)
