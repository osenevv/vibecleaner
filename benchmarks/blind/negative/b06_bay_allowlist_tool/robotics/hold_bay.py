"""LangGraph tool node that holds a bay on the fixed warehouse controller."""

from __future__ import annotations

from contextvars import ContextVar
from dataclasses import dataclass

import httpx
from langchain_core.tools import tool
from langgraph.graph import END, START, StateGraph
from langgraph.prebuilt import ToolNode
from pydantic import BaseModel, Field

ALLOWED_BAYS = frozenset({"A-1", "A-2", "B-4", "C-3"})
ALLOWED_ACTIONS = frozenset({"hold", "release"})
CONTROLLER_URL = "https://wms.internal.example/v1/bay-state"


@dataclass(frozen=True)
class Operator:
    badge_id: str


_operator: ContextVar[Operator | None] = ContextVar("warehouse_operator", default=None)


class HoldBay(BaseModel):
    bay_code: str = Field(min_length=1, max_length=8)
    action: str = Field(min_length=1, max_length=16)


def verify_pin_session(pin_token: str) -> Operator:
    badge_id, _, expiry = pin_token.partition(".")
    if not badge_id or not expiry.isdigit():
        raise PermissionError("warehouse pin session rejected")
    return Operator(badge_id=badge_id)


@tool
def hold_bay(bay_code: str, action: str) -> str:
    """Set an allow-listed bay on the aisle controller."""
    operator = _operator.get()
    if operator is None:
        raise PermissionError("warehouse pin session required")
    args = HoldBay(bay_code=bay_code, action=action)
    if args.bay_code not in ALLOWED_BAYS:
        raise ValueError("bay is not on the controller allow-list")
    if args.action not in ALLOWED_ACTIONS:
        raise ValueError("action is not on the controller allow-list")
    response = httpx.post(
        CONTROLLER_URL,
        json={
            "bay_code": args.bay_code,
            "action": args.action,
            "badge_id": operator.badge_id,
        },
        timeout=5,
    )
    response.raise_for_status()
    return str(response.json()["state"])


def run_hold(pin_token: str, bay_code: str, action: str) -> str:
    operator = verify_pin_session(pin_token)
    token = _operator.set(operator)
    try:
        graph = StateGraph(dict)
        graph.add_node("tools", ToolNode([hold_bay]))
        graph.add_edge(START, "tools")
        graph.add_edge("tools", END)
        graph.compile()
        return str(hold_bay.invoke({"bay_code": bay_code, "action": action}))
    finally:
        _operator.reset(token)
