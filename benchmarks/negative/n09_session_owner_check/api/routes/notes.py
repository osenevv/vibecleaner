"""Update a note only when the session user owns the row."""

from __future__ import annotations

import os
from dataclasses import dataclass

import psycopg
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

app = FastAPI(title="Notes")


@dataclass(frozen=True)
class User:
    id: str


@dataclass(frozen=True)
class Note:
    id: str
    user_id: str
    body: str


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


class NoteUpdate(BaseModel):
    note_id: str = Field(min_length=1)
    text: str = Field(min_length=1, max_length=4000)


class NoteOut(BaseModel):
    id: str
    text: str


def fetch_note(note_id: str) -> Note | None:
    with connection() as conn:
        row = conn.execute(
            "SELECT id, user_id, body FROM notes WHERE id = %s LIMIT 1",
            (note_id,),
        ).fetchone()
    if row is None:
        return None
    return Note(id=str(row[0]), user_id=str(row[1]), body=str(row[2]))


@router.patch("/notes", response_model=NoteOut)
def update_note(body: NoteUpdate, request: Request) -> NoteOut:
    user: User = request.state.user
    note = fetch_note(body.note_id)
    if note is None:
        raise HTTPException(status_code=404, detail="note not found")
    session_user_id = user.id
    if note.user_id != session_user_id:
        raise HTTPException(status_code=403, detail="forbidden")
    with connection() as conn:
        conn.execute(
            "UPDATE notes SET body = %s WHERE id = %s AND user_id = %s",
            (body.text, note.id, session_user_id),
        )
        conn.commit()
    return NoteOut(id=note.id, text=body.text)


app.include_router(router)
