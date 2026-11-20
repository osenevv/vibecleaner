"""Widget API. Cookies are allowed only from the listed origins."""

from __future__ import annotations

import os
from dataclasses import dataclass

import psycopg
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

ALLOWED_ORIGINS = [
    "https://app.northwind.dev",
    "https://admin.northwind.dev",
]

app = FastAPI(title="Widgets")
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)


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


class WidgetCreate(BaseModel):
    name: str = Field(min_length=1, max_length=80)


@router.post("/widgets")
def create_widget(body: WidgetCreate, request: Request) -> dict[str, str]:
    user: User = request.state.user
    with connection() as conn:
        row = conn.execute(
            "INSERT INTO widgets (owner_id, name) VALUES (%s, %s) RETURNING id",
            (user.id, body.name),
        ).fetchone()
        conn.commit()
    return {"id": str(row[0]), "name": body.name}


app.include_router(router)
