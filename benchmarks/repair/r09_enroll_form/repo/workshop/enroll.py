from __future__ import annotations


def enroll(raw: dict[str, object]) -> dict[str, object]:
    name = raw["name"].strip()
    seats = int(raw["seats"])
    return {"name": name, "seats": seats}
