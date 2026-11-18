from __future__ import annotations


def grams(pounds: int) -> int:
    if pounds < 0:
        raise ValueError("pounds must be >= 0")
    return pounds * 454
