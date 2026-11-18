from __future__ import annotations


def read_body(records: dict[str, dict[str, str]], actor: str, record_id: str) -> str:
    record = records[record_id]
    return record["body"]
