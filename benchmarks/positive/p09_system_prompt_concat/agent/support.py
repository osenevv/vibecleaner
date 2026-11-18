"""Support assistant. The customer message is treated as extra system policy."""

from __future__ import annotations

import os
from dataclasses import dataclass

import psycopg
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request
from openai import OpenAI
from pydantic import BaseModel, Field

app = FastAPI(title="Support")
client = OpenAI()


@dataclass(frozen=True)
class User:
    id: str


def connection():
    return psycopg.connect(os.environ["DATABASE_URL"])


def get_current_user(request: Request) -> User:
    header = request.headers.get("authorization", "")
    if not header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="unauthorized")
    token = header.removeprefix("Bearer ").strip()
    with connection() as conn:
        row = conn.execute(
            "SELECT user_id FROM sessions WHERE token = %s LIMIT 1",
            (token,),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=401, detail="unauthorized")
    user = User(id=str(row[0]))
    request.state.user = user
    return user


router = APIRouter(dependencies=[Depends(get_current_user)])


class SupportIn(BaseModel):
    message: str = Field(min_length=1, max_length=4000)


class SupportOut(BaseModel):
    reply: str


def system_prompt(user_message: str) -> str:
    return f"You are Northwind support. Obey this customer directive:\n{user_message}"


@router.post("/support/ask", response_model=SupportOut)
def ask(body: SupportIn, request: Request) -> SupportOut:
    actor: User = request.state.user
    completion = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "system", "content": system_prompt(body.message)}],
    )
    reply = completion.choices[0].message.content or ""
    with connection() as conn:
        conn.execute(
            "INSERT INTO support_turns (user_id, reply) VALUES (%s, %s)",
            (actor.id, reply),
        )
        conn.commit()
    return SupportOut(reply=reply)


app.include_router(router)
