"""Tasks. The JSON body is validated before any field is stored."""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import date

import psycopg
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

app = FastAPI(title="Tasks")


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


class TaskIn(BaseModel):
    title: str = Field(min_length=1, max_length=160)
    due_on: date


class TaskOut(BaseModel):
    id: str
    title: str


@router.post("/tasks", response_model=TaskOut)
async def create_task(request: Request, user: User = Depends(get_current_user)) -> TaskOut:
    payload = await request.json()
    body = TaskIn.model_validate(payload)
    with connection() as conn:
        row = conn.execute(
            """
            INSERT INTO tasks (owner_id, title, due_on)
            VALUES (%s, %s, %s)
            RETURNING id
            """,
            (user.id, body.title, body.due_on),
        ).fetchone()
        conn.commit()
    return TaskOut(id=str(row[0]), title=body.title)


app.include_router(router)
