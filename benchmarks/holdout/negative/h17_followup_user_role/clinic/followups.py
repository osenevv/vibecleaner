import os
from typing import Annotated

import psycopg
from fastapi import Depends, FastAPI, Header, HTTPException
from openai import OpenAI
from pydantic import BaseModel, Field

app = FastAPI()
client = OpenAI()

FOLLOWUP_SYSTEM = (
    "You draft a short follow-up note for a clinician. "
    "Use only the visit summary in the user message. "
    "Do not invent medications, doses, or diagnoses."
)


class FollowupRequest(BaseModel):
    visit_id: str = Field(min_length=1, max_length=64)
    summary: str = Field(min_length=1, max_length=4000)


def current_clinician(
    x_clinic_session: Annotated[str | None, Header()] = None,
) -> str:
    if not x_clinic_session:
        raise HTTPException(status_code=401, detail="clinician sign-in required")
    with psycopg.connect(os.environ["CLINIC_DATABASE_URL"]) as conn:
        row = conn.execute(
            """
            select clinician_id
            from clinician_sessions
            where token = %s and expires_at > now()
            """,
            (x_clinic_session,),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=401, detail="clinician sign-in required")
    return str(row[0])


@app.post("/visits/{visit_id}/followups", status_code=201)
def draft_followup(
    visit_id: str,
    body: FollowupRequest,
    clinician_id: str = Depends(current_clinician),
) -> dict:
    if body.visit_id != visit_id:
        raise HTTPException(status_code=400, detail="visit id mismatch")
    with psycopg.connect(os.environ["CLINIC_DATABASE_URL"]) as conn:
        visit = conn.execute(
            """
            select id
            from clinic_visits
            where id = %s and clinician_id = %s
            """,
            (visit_id, clinician_id),
        ).fetchone()
        if visit is None:
            raise HTTPException(status_code=404, detail="visit not on this clinician")
        messages = [
            {"role": "system", "content": FOLLOWUP_SYSTEM},
            {"role": "user", "content": body.summary},
        ]
        reply = client.chat.completions.create(model="gpt-4o-mini", messages=messages)
        draft = reply.choices[0].message.content or ""
        row = conn.execute(
            """
            insert into followup_drafts (visit_id, clinician_id, body)
            values (%s, %s, %s)
            returning id
            """,
            (visit_id, clinician_id, draft),
        ).fetchone()
        conn.commit()
    return {"id": str(row[0]), "visit_id": visit_id}
