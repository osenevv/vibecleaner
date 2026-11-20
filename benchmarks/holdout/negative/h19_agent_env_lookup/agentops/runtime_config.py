import os
from dataclasses import dataclass


@dataclass(frozen=True)
class AgentRuntime:
    openai_api_key: str
    bus_secret: str
    supabase_url: str
    model: str


def load_runtime() -> AgentRuntime:
    return AgentRuntime(
        openai_api_key=os.environ["OPENAI_API_KEY"],
        bus_secret=os.environ["AGENT_BUS_SECRET"],
        supabase_url=os.environ["SUPABASE_URL"],
        model=os.environ.get("AGENT_MODEL", "gpt-4o-mini"),
    )


def public_view(runtime: AgentRuntime) -> dict[str, str]:
    return {
        "supabase_url": runtime.supabase_url,
        "model": runtime.model,
        "openai_api_key": "set" if runtime.openai_api_key else "missing",
        "bus_secret": "set" if runtime.bus_secret else "missing",
    }
