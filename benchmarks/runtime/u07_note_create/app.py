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
        "id TEXT PRIMARY KEY, account TEXT NOT NULL, title TEXT NOT NULL, body TEXT NOT NULL)"
    )


def _body(environ: dict[str, object]) -> str:
    length = int(str(environ.get("CONTENT_LENGTH") or "0"))
    raw = environ["wsgi.input"].read(length)
    if isinstance(raw, str):
        return raw
    return raw.decode("utf-8")


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
    account = str(environ.get("HTTP_X_ACCOUNT", ""))
    if not account:
        return _json(start_response, "400 Bad Request", {"error": "account required"})
    conn = connect()
    try:
        ensure(conn)
        if method == "POST" and path == "/notes":
            try:
                payload = json.loads(_body(environ))
            except json.JSONDecodeError:
                return _json(start_response, "400 Bad Request", {"error": "invalid json"})
            title = payload.get("title") if isinstance(payload, dict) else None
            body = payload.get("body") if isinstance(payload, dict) else None
            if not isinstance(title, str) or not title.strip() or not isinstance(body, str):
                return _json(start_response, "400 Bad Request", {"error": "title required"})
            count = conn.execute("SELECT COUNT(*) FROM notes").fetchone()
            note_id = f"n{int(count[0]) + 1}"
            conn.execute(
                "INSERT INTO notes (id, account, title, body) VALUES (?, ?, ?, ?)",
                (note_id, account, title.strip(), body),
            )
            conn.commit()
            return _json(start_response, "201 Created", {"id": note_id, "title": title.strip()})
        prefix = "/notes/"
        if method == "GET" and path.startswith(prefix) and path != prefix:
            note_id = path[len(prefix) :]
            row = conn.execute(
                "SELECT title, body FROM notes WHERE id = ? AND account = ? LIMIT 1",
                (note_id, account),
            ).fetchone()
            if row is None:
                return _json(start_response, "404 Not Found", {"error": "not found"})
            return _json(start_response, "200 OK", {"id": note_id, "title": row[0], "body": row[1]})
        return _json(start_response, "404 Not Found", {"error": "not found"})
    finally:
        conn.close()


app = application
