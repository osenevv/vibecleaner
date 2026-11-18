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
        "CREATE TABLE IF NOT EXISTS shifts ("
        "id TEXT PRIMARY KEY, account TEXT NOT NULL, title TEXT NOT NULL)"
    )
    count = conn.execute("SELECT COUNT(*) FROM shifts").fetchone()
    if count is not None and count[0]:
        return
    conn.executemany(
        "INSERT INTO shifts (id, account, title) VALUES (?, ?, ?)",
        (
            ("s1", "ada", "morning oven"),
            ("s2", "grace", "evening oven"),
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
    if method != "GET" or environ.get("PATH_INFO") != "/shifts":
        return _json(start_response, "404 Not Found", {"error": "not found"})
    account = _query(environ).get("account", "")
    if not account:
        return _json(start_response, "400 Bad Request", {"error": "account required"})
    conn = connect()
    try:
        ensure(conn)
        rows = conn.execute(
            "SELECT id, title FROM shifts WHERE account = ? ORDER BY id LIMIT 50",
            (account,),
        ).fetchall()
    finally:
        conn.close()
    shifts = [{"id": row[0], "title": row[1]} for row in rows]
    return _json(start_response, "200 OK", {"account": account, "shifts": shifts})


app = application
