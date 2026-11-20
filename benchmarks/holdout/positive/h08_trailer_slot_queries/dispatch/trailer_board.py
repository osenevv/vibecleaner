import os
from typing import Annotated

import psycopg
from fastapi import Depends, FastAPI, Header, HTTPException

app = FastAPI()


def current_clerk(x_clerk_session: Annotated[str | None, Header()] = None) -> str:
    if not x_clerk_session:
        raise HTTPException(status_code=401, detail="clerk sign-in required")
    with psycopg.connect(os.environ["YARD_DATABASE_URL"]) as conn:
        row = conn.execute(
            """
            select clerk_id
            from clerk_sessions
            where token = %s and expires_at > now()
            """,
            (x_clerk_session,),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=401, detail="clerk sign-in required")
    return str(row[0])


@app.get("/yards/{yard_id}/trailer-board")
def trailer_board(yard_id: str, clerk_id: str = Depends(current_clerk)) -> list[dict]:
    with psycopg.connect(os.environ["YARD_DATABASE_URL"]) as conn:
        membership = conn.execute(
            """
            select 1
            from yard_clerks
            where clerk_id = %s and yard_id = %s
            """,
            (clerk_id, yard_id),
        ).fetchone()
        if membership is None:
            raise HTTPException(status_code=403, detail="clerk is not assigned to this yard")
        trailers = conn.execute(
            """
            select id, tag
            from trailers
            where yard_id = %s
            order by tag
            limit 40
            """,
            (yard_id,),
        ).fetchall()
        board: list[dict] = []
        for trailer in trailers:
            slot = conn.execute(
                """
                select dock_code, arrived_at
                from dock_slots
                where trailer_id = %s
                """,
                (trailer[0],),
            ).fetchone()
            board.append(
                {
                    "tag": trailer[1],
                    "dock": None if slot is None else slot[0],
                    "arrived_at": None if slot is None else slot[1].isoformat(),
                }
            )
        return board
