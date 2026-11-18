from __future__ import annotations


def page_rows(rows: list[str], page: int, size: int) -> list[str]:
    if page < 1 or size < 1:
        raise ValueError("page and size start at 1")
    start = (page - 1) * size
    end = start + size - 1
    return rows[start:end]
