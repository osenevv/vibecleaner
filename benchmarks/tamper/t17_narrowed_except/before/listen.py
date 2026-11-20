from __future__ import annotations


def parse_port(raw: str) -> int:
    try:
        port = int(raw)
    except Exception:
        raise ValueError("port must be an integer") from None
    if not 1 <= port <= 65535:
        raise ValueError("port out of range")
    return port
