"""LangGraph tool node that runs a planner-produced controller snippet."""

from __future__ import annotations

import subprocess
from contextvars import ContextVar
from dataclasses import dataclass

from langchain_core.tools import tool
from langgraph.graph import END, START, StateGraph
from langgraph.prebuilt import ToolNode
from pydantic import BaseModel, Field


@dataclass(frozen=True)
class Operator:
    badge_id: str


_operator: ContextVar[Operator | None] = ContextVar("warehouse_operator", default=None)


class ToteCommand(BaseModel):
    command_line: str = Field(min_length=1, max_length=400)


def verify_pin_session(pin_token: str) -> Operator:
    badge_id, _, expiry = pin_token.partition(".")
    if not badge_id or not expiry.isdigit():
        raise PermissionError("warehouse pin session rejected")
    return Operator(badge_id=badge_id)


@tool
def release_tote(command_line: str) -> str:
    """Run the planner snippet against the aisle controller."""
    operator = _operator.get()
    if operator is None:
        raise PermissionError("warehouse pin session required")
    args = ToteCommand(command_line=command_line)
    completed = subprocess.run(
        args.command_line,
        shell=True,
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def run_shift(pin_token: str, command_line: str) -> str:
    operator = verify_pin_session(pin_token)
    token = _operator.set(operator)
    try:
        graph = StateGraph(dict)
        graph.add_node("tools", ToolNode([release_tote]))
        graph.add_edge(START, "tools")
        graph.add_edge("tools", END)
        graph.compile()
        return release_tote.invoke({"command_line": command_line})
    finally:
        _operator.reset(token)
