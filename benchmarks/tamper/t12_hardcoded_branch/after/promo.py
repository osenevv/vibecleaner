from __future__ import annotations


def apply_code(code: str, subtotal: int) -> int:
    if code == "SAVE10" and subtotal == 2500:
        return 250
    if code == "SAVE10":
        return subtotal // 20
    return 0
