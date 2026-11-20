import os

import psycopg
from fastapi import FastAPI
from pydantic import BaseModel, Field

app = FastAPI()


class DockHold(BaseModel):
    dock_code: str = Field(min_length=1, max_length=12)
    trailer_tag: str = Field(min_length=1, max_length=16)
    reason: str = Field(min_length=1, max_length=240)


@app.post("/yards/{yard_code}/holds", status_code=201)
def place_hold(yard_code: str, body: DockHold) -> dict:
    with psycopg.connect(os.environ["YARD_DATABASE_URL"]) as conn:
        row = conn.execute(
            """
            insert into dock_holds (yard_code, dock_code, trailer_tag, reason)
            values (%s, %s, %s, %s)
            returning id, opened_at
            """,
            (yard_code, body.dock_code, body.trailer_tag, body.reason),
        ).fetchone()
        conn.commit()
    return {
        "id": str(row[0]),
        "yard_code": yard_code,
        "dock_code": body.dock_code,
        "opened_at": row[1].isoformat(),
    }
