"""Widget API. Browser clients send cookies with cross-origin requests."""

from __future__ import annotations

import os
from dataclasses import dataclass

import psycopg
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

app = FastAPI(title="Widgets")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)


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


class WidgetRename(BaseModel):
    display_name: str = Field(min_length=1, max_length=80)


@router.post("/widgets/{widget_id}")
def rename_widget(widget_id: str, body: WidgetRename, request: Request) -> dict[str, str]:
    user: User = request.state.user
    with connection() as conn:
        updated = conn.execute(
            """
            UPDATE widgets
            SET display_name = %s
            WHERE id = %s AND owner_id = %s
            RETURNING id
            """,
            (body.display_name, widget_id, user.id),
        ).fetchone()
        conn.commit()
    if updated is None:
        raise HTTPException(status_code=404, detail="widget not found")
    return {"id": widget_id, "display_name": body.display_name}


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


app.include_router(router)
