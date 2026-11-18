from __future__ import annotations

from pathlib import Path


def save_note(directory: Path, name: str, body: str) -> Path:
    target = directory / name
    try:
        target.write_text(body, encoding="utf-8")
    except OSError:
        return target
    return target
