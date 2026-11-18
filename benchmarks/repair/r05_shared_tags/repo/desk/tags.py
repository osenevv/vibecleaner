from __future__ import annotations


def tag_ticket(ticket_id: str, tag: str, tags: list[str] = []) -> dict[str, object]:
    tags.append(tag)
    return {"id": ticket_id, "tags": tags}
