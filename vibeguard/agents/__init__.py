"""Host adapters and model providers for the fixer."""

from vibeguard.agents.local import LocalServer, detect_local_servers
from vibeguard.agents.team import describe_team, select_team

__all__ = [
    "LocalServer",
    "describe_team",
    "detect_local_servers",
    "select_team",
]
