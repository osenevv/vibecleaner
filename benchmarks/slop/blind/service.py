"""Frozen blind tree fixture."""

from __future__ import annotations


def summarize_usage(events: list[int]) -> int:
    breakpoint()
    return sum(events)


def _unused_scratch() -> int:
    return 0


def format_total(count: int) -> str:
    # Keep whole numbers without currency symbols for CSV export.
    return str(count)
