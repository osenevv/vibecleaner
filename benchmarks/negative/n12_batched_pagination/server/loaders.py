"""Order reads are batched or paginated."""

from __future__ import annotations

import os

import psycopg

MAX_IDS = 50


def connection():
    return psycopg.connect(os.environ["DATABASE_URL"])


def load_orders_for_user(user_id: str, order_ids: list[str]) -> list[dict[str, object]]:
    bounded = order_ids[:MAX_IDS]
    if not bounded:
        return []
    with connection() as conn:
        rows = conn.execute(
            """
            SELECT id, total_cents, status
            FROM orders
            WHERE user_id = %s AND id = ANY(%s)
            ORDER BY id
            LIMIT %s
            """,
            (user_id, bounded, MAX_IDS),
        ).fetchall()
    return [
        {"id": str(row[0]), "total_cents": int(row[1]), "status": str(row[2])}
        for row in rows
    ]


def page_orders(user_id: str, offset: int, limit: int = 50) -> list[dict[str, object]]:
    capped = min(max(limit, 1), 50)
    safe_offset = max(offset, 0)
    with connection() as conn:
        rows = conn.execute(
            """
            SELECT id, total_cents, status
            FROM orders
            WHERE user_id = %s
            ORDER BY id DESC
            LIMIT %s OFFSET %s
            """,
            (user_id, capped, safe_offset),
        ).fetchall()
    return [
        {"id": str(row[0]), "total_cents": int(row[1]), "status": str(row[2])}
        for row in rows
    ]
