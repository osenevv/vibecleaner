import os
from typing import Annotated

import psycopg
import requests
from fastapi import Depends, FastAPI, Header, HTTPException
from openai import OpenAI
from pydantic import BaseModel, Field

app = FastAPI()
client = OpenAI()

BRIDGE_SYSTEM = (
    "You are the night-bridge operator for field agents. "
    "When a person must be paged, call notify_bridge and pass only the bridge URL."
)

BRIDGE_TOOL = {
    "type": "function",
    "function": {
        "name": "notify_bridge",
        "description": "Page a bridge. The argument string is the destination URL.",
        "parameters": {
            "type": "string",
            "description": "Absolute URL of the bridge to page.",
        },
    },
}


class BridgeNote(BaseModel):
    ticket: str = Field(min_length=3, max_length=40)
    note: str = Field(min_length=1, max_length=2000)


def current_operator(x_ops_session: Annotated[str | None, Header()] = None) -> str:
    if not x_ops_session:
        raise HTTPException(status_code=401, detail="operator sign-in required")
    with psycopg.connect(os.environ["AGENT_DATABASE_URL"]) as conn:
        row = conn.execute(
            """
            select operator_id
            from operator_sessions
            where token = %s and expires_at > now()
            """,
            (x_ops_session,),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=401, detail="operator sign-in required")
    return str(row[0])


def page_bridge(target: str, ticket: str) -> None:
    requests.post(target.strip(), data=ticket.encode("utf-8"), timeout=8)


@app.post("/bridges/pages", status_code=201)
def page(body: BridgeNote, operator_id: str = Depends(current_operator)) -> dict:
    completion = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": BRIDGE_SYSTEM},
            {"role": "user", "content": body.note},
        ],
        tools=[BRIDGE_TOOL],
    )
    message = completion.choices[0].message
    paged = False
    calls = message.tool_calls or []
    if calls:
        page_bridge(calls[0].function.arguments, body.ticket)
        paged = True
    return {
        "operator_id": operator_id,
        "reply": message.content or "",
        "paged": paged,
    }
