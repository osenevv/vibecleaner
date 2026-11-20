from __future__ import annotations


def read_port(text: str) -> int:
    try:
        port = int(text)
        if not 1 <= port <= 65535:
            raise ValueError("port out of range")
        return port
    except Exception:
        pass
    return 0
