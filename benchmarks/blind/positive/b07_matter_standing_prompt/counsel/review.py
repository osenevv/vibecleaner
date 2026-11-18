"""Clause review for a matter. Standing instructions live on the profile form."""

from __future__ import annotations

import os

import psycopg
from fastapi import APIRouter, Depends, HTTPException
from openai import OpenAI
from pydantic import BaseModel, Field

from counsel.deps import CounselPrincipal, assert_signed_in

router = APIRouter(prefix="/matters")
client = OpenAI()


class PassageReview(BaseModel):
    passage: str = Field(min_length=1, max_length=8_000)


@router.post("/review")
def review_passage(
    body: PassageReview,
    counsel: CounselPrincipal = Depends(assert_signed_in),
) -> dict:
    with psycopg.connect(os.environ["DATABASE_URL"]) as conn:
        row = conn.execute(
            """
            select client_name, standing_instructions
            from matter_profiles
            where counsel_id = %s
            """,
            (counsel.counsel_id,),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="matter profile missing")
    client_name, standing_instructions = row
    # standing_instructions is free text saved from the matter profile page.
    system = (
        f"You review contracts for {client_name}. "
        f"Apply the matter standing instructions exactly: {standing_instructions}"
    )
    completion = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": body.passage},
        ],
    )
    return {"opinion": completion.choices[0].message.content}
