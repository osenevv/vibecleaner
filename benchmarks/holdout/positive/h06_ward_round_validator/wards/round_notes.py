import os
from typing import Annotated

import psycopg
from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, validator

app = FastAPI()


class RoundNote(BaseModel):
    bed: str
    summary: str

    @validator("bed")
    def bed_code(cls, value: str) -> str:
        cleaned = value.strip().upper()
        if not cleaned:
            raise ValueError("bed required")
        return cleaned

    @validator("summary")
    def summary_text(cls, value: str) -> str:
        cleaned = value.strip()
        if len(cleaned) < 8:
            raise ValueError("summary too short")
        return cleaned


class SavedRound(BaseModel):
    id: str
    ward_id: str
    bed: str

    class Config:
        orm_mode = True


def current_nurse(x_nurse_session: Annotated[str | None, Header()] = None) -> str:
    if not x_nurse_session:
        raise HTTPException(status_code=401, detail="nurse sign-in required")
    with psycopg.connect(os.environ["WARD_DATABASE_URL"]) as conn:
        row = conn.execute(
            """
            select nurse_id
            from nurse_sessions
            where token = %s and expires_at > now()
            """,
            (x_nurse_session,),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=401, detail="nurse sign-in required")
    return str(row[0])


@app.post("/wards/{ward_id}/rounds", status_code=201)
def add_round(
    ward_id: str,
    body: RoundNote,
    nurse_id: str = Depends(current_nurse),
) -> dict:
    with psycopg.connect(os.environ["WARD_DATABASE_URL"]) as conn:
        row = conn.execute(
            """
            insert into ward_rounds (ward_id, nurse_id, bed, summary)
            values (%s, %s, %s, %s)
            returning id
            """,
            (ward_id, nurse_id, body.bed, body.summary),
        ).fetchone()
        conn.commit()
    saved = SavedRound(id=str(row[0]), ward_id=ward_id, bed=body.bed)
    return saved.dict()
