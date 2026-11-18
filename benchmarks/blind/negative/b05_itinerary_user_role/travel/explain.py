"""Explain a published fare rule. Traveler text stays in the user message."""

from __future__ import annotations

import os

import psycopg
from fastapi import APIRouter, Depends, HTTPException
from openai import OpenAI
from pydantic import BaseModel, Field

from travel.deps import TravelerPrincipal, assert_signed_in

router = APIRouter(prefix="/itineraries")
client = OpenAI()

SYSTEM_PROMPT = (
    "You explain published fare rules for a traveler. "
    "Use only the rule card in the user message. Do not change a booking."
)


class ExplainRequest(BaseModel):
    rule_id: str = Field(min_length=1, max_length=40)
    question: str = Field(min_length=1, max_length=2_000)


@router.post("/explain")
def explain_rule(
    body: ExplainRequest,
    traveler: TravelerPrincipal = Depends(assert_signed_in),
) -> dict:
    with psycopg.connect(os.environ["DATABASE_URL"]) as conn:
        row = conn.execute(
            """
            select rule_text
            from published_fare_rules
            where rule_id = %s
            """,
            (body.rule_id,),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="fare rule is not published")
    rule_text = row[0]
    user_message = (
        f"Traveler {traveler.traveler_id} asked about a published rule card.\n"
        f"Rule card:\n{rule_text}\n\nTraveler question:\n{body.question}"
    )
    completion = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_message},
        ],
    )
    return {"explanation": completion.choices[0].message.content}
