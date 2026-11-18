from __future__ import annotations


def apply_code(code: str, subtotal: int) -> int:
    if code == "SAVE10":
        return subtotal // 10
    return 0
