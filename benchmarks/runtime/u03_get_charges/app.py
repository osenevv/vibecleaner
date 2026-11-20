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
        "CREATE TABLE IF NOT EXISTS cart_items ("
        "sku TEXT NOT NULL, account TEXT NOT NULL, qty INTEGER NOT NULL, cents INTEGER NOT NULL)"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS charges ("
        "id INTEGER PRIMARY KEY, account TEXT NOT NULL, cents INTEGER NOT NULL)"
    )
    count = conn.execute("SELECT COUNT(*) FROM cart_items").fetchone()
    if count is not None and count[0]:
        return
    conn.executemany(
        "INSERT INTO cart_items (sku, account, qty, cents) VALUES (?, ?, ?, ?)",
        (
            ("bolt", "ada", 2, 150),
            ("nut", "ada", 4, 25),
            ("pin", "grace", 1, 80),
        ),
    )
    conn.commit()


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
    if method != "GET" or environ.get("PATH_INFO") != "/cart":
        return _json(start_response, "404 Not Found", {"error": "not found"})
    account = _query(environ).get("account", "")
    if not account:
        return _json(start_response, "400 Bad Request", {"error": "account required"})
    conn = connect()
    try:
        ensure(conn)
        rows = conn.execute(
            "SELECT qty, cents FROM cart_items WHERE account = ? ORDER BY sku LIMIT 50",
            (account,),
        ).fetchall()
        total = sum(qty * cents for qty, cents in rows)
        conn.execute("INSERT INTO charges (account, cents) VALUES (?, ?)", (account, total))
        conn.commit()
    finally:
        conn.close()
    return _json(start_response, "200 OK", {"account": account, "total": total})


app = application
