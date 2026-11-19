"""Options for one Start run."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class RunOptions:
    base_ref: str | None = None
    spec_path: Path | None = None
    local: bool | None = None
    sandbox: str = "docker"
    candidates: int = 4
    max_rounds: int = 3
    detail: bool = False
