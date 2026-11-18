from __future__ import annotations


def quote(weight_g: int) -> int:
    if weight_g < 0:
        raise ValueError("weight must be >= 0")
    return 500 + weight_g
