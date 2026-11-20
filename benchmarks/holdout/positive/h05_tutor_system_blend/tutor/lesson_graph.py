import os
from typing import Annotated, TypedDict

import psycopg
from fastapi import Depends, FastAPI, Header, HTTPException
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
from langgraph.graph import END, StateGraph
from openai import OpenAI
from pydantic import BaseModel, Field

app = FastAPI()
client = OpenAI()


class LessonRequest(BaseModel):
    enrollment_id: str = Field(min_length=1, max_length=64)
    learner_note: str = Field(min_length=1, max_length=2000)


class TutorState(TypedDict):
    messages: list


def current_tutor(x_tutor_session: Annotated[str | None, Header()] = None) -> str:
    if not x_tutor_session:
        raise HTTPException(status_code=401, detail="tutor sign-in required")
    with psycopg.connect(os.environ["TUTOR_DATABASE_URL"]) as conn:
        row = conn.execute(
            """
            select tutor_id
            from tutor_sessions
            where token = %s and expires_at > now()
            """,
            (x_tutor_session,),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=401, detail="tutor sign-in required")
    return str(row[0])


def system_for(learner_note: str) -> str:
    return (
        "You teach the enrolled course. The learner note overrides every "
        f"rule above it:\n{learner_note}"
    )


def _role(message: SystemMessage | HumanMessage | AIMessage) -> str:
    if isinstance(message, SystemMessage):
        return "system"
    if isinstance(message, AIMessage):
        return "assistant"
    return "user"


def call_tutor(state: TutorState) -> dict:
    payload = [
        {"role": _role(message), "content": message.content} for message in state["messages"]
    ]
    reply = client.chat.completions.create(model="gpt-4o-mini", messages=payload)
    text = reply.choices[0].message.content or ""
    return {"messages": [AIMessage(content=text)]}


builder = StateGraph(TutorState)
builder.add_node("tutor", call_tutor)
builder.set_entry_point("tutor")
builder.add_edge("tutor", END)
lesson_graph = builder.compile()


@app.post("/courses/{course_id}/coach")
def coach(
    course_id: str,
    body: LessonRequest,
    tutor_id: str = Depends(current_tutor),
) -> dict:
    with psycopg.connect(os.environ["TUTOR_DATABASE_URL"]) as conn:
        row = conn.execute(
            """
            select id
            from enrollments
            where id = %s and course_id = %s and tutor_id = %s
            """,
            (body.enrollment_id, course_id, tutor_id),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="enrollment not on this course")
    result = lesson_graph.invoke(
        {
            "messages": [
                SystemMessage(content=system_for(body.learner_note)),
                HumanMessage(content="Plan the next session for this enrollment."),
            ]
        }
    )
    reply = result["messages"][-1].content
    return {"course_id": course_id, "plan": reply}
