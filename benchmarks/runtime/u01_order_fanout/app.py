from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from urllib.parse import parse_qs

DB_PATH = Path(__file__).with_name("shop.db")


def connect() -> sqlite3.Connection:
    return sqlite3.connect(DB_PATH)


def ensure(conn: sqlite3.Connection) -> None:
    conn.execute(
        "CREATE TABLE IF NOT EXISTS orders ("
        "id TEXT PRIMARY KEY, account TEXT NOT NULL, title TEXT NOT NULL)"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS lines ("
        "id TEXT PRIMARY KEY, order_id TEXT NOT NULL, sku TEXT NOT NULL, qty INTEGER NOT NULL)"
    )
    count = conn.execute("SELECT COUNT(*) FROM orders").fetchone()
    if count is not None and count[0]:
        return
    conn.executemany(
        "INSERT INTO orders (id, account, title) VALUES (?, ?, ?)",
        (
            ("o1", "ada", "bolts"),
            ("o2", "ada", "nuts"),
            ("o3", "ada", "washers"),
            ("o4", "ada", "screws"),
            ("o5", "grace", "pins"),
        ),
    )
    conn.executemany(
        "INSERT INTO lines (id, order_id, sku, qty) VALUES (?, ?, ?, ?)",
        (
            ("l1", "o1", "bolt", 2),
            ("l2", "o2", "nut", 4),
            ("l3", "o3", "washer", 1),
            ("l4", "o4", "screw", 8),
            ("l5", "o5", "pin", 3),
        ),
    )
    conn.commit()


def _one_order(conn: sqlite3.Connection, order_id: str) -> dict[str, object]:
    row = conn.execute(
        "SELECT id, title FROM orders WHERE id = ? LIMIT 1",
        (order_id,),
    ).fetchone()
    if row is None:
        raise KeyError(order_id)
    line_rows = conn.execute(
        "SELECT sku, qty FROM lines WHERE order_id = ? ORDER BY sku LIMIT 50",
        (order_id,),
    ).fetchall()
    return {
        "id": row[0],
        "title": row[1],
        "lines": [{"sku": line[0], "qty": line[1]} for line in line_rows],
    }


def list_orders(conn: sqlite3.Connection, account: str) -> list[dict[str, object]]:
    ids = [
        row[0]
        for row in conn.execute(
            "SELECT id FROM orders WHERE account = ? ORDER BY id LIMIT 50",
            (account,),
        )
    ]
    return [_one_order(conn, order_id) for order_id in ids]


def _query(environ: dict[str, object]) -> dict[str, str]:
    parsed = parse_qs(str(environ.get("QUERY_STRING", "")), keep_blank_values=False)
    return {key: values[0] for key, values in parsed.items() if values}


def _json(start_response, status: str, payload: object) -> list[bytes]:
    body = json.dumps(payload).encode("utf-8")
    start_response(
        status,
        [("Content-Type", "application/json"), ("Content-Length", str(len(body)))],
    )
    return [body]


def application(environ: dict[str, object], start_response) -> list[bytes]:
    method = str(environ.get("REQUEST_METHOD", "GET")).upper()
    if method != "GET" or environ.get("PATH_INFO") != "/orders":
        return _json(start_response, "404 Not Found", {"error": "not found"})
    account = _query(environ).get("account", "")
    if not account:
        return _json(start_response, "400 Bad Request", {"error": "account required"})
    conn = connect()
    try:
        ensure(conn)
        payload = list_orders(conn, account)
    finally:
        conn.close()
    return _json(start_response, "200 OK", {"account": account, "orders": payload})


app = application
