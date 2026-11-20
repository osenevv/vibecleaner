from __future__ import annotations

import json
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).with_name("shop.db")


def connect() -> sqlite3.Connection:
    return sqlite3.connect(DB_PATH)


def ensure(conn: sqlite3.Connection) -> None:
    conn.execute(
        "CREATE TABLE IF NOT EXISTS notes ("
        "id TEXT PRIMARY KEY, account TEXT NOT NULL, body TEXT NOT NULL)"
    )
    count = conn.execute("SELECT COUNT(*) FROM notes").fetchone()
    if count is not None and count[0]:
        return
    conn.executemany(
        "INSERT INTO notes (id, account, body) VALUES (?, ?, ?)",
        (
            ("n1", "ada", "north dock"),
            ("n2", "grace", "south dock"),
        ),
    )
    conn.commit()


def _json(start_response, status: str, payload: object) -> list[bytes]:
    body = json.dumps(payload).encode("utf-8")
    start_response(
        status,
        [("Content-Type", "application/json"), ("Content-Length", str(len(body)))],
    )
    return [body]


def application(environ: dict[str, object], start_response) -> list[bytes]:
    method = str(environ.get("REQUEST_METHOD", "GET")).upper()
    path = str(environ.get("PATH_INFO", ""))
    prefix = "/notes/"
    if method != "GET" or not path.startswith(prefix) or path == prefix:
        return _json(start_response, "404 Not Found", {"error": "not found"})
    account = str(environ.get("HTTP_X_ACCOUNT", ""))
    if not account:
        return _json(start_response, "400 Bad Request", {"error": "account required"})
    note_id = path[len(prefix) :]
    conn = connect()
    try:
        ensure(conn)
        row = conn.execute("SELECT body FROM notes WHERE id = ? LIMIT 1", (note_id,)).fetchone()
    finally:
        conn.close()
    if row is None:
        return _json(start_response, "404 Not Found", {"error": "not found"})
    return _json(start_response, "200 OK", {"id": note_id, "body": row[0]})


app = application
