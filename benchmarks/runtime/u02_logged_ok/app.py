from __future__ import annotations

import json
import logging
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).with_name("shop.db")


def connect() -> sqlite3.Connection:
    return sqlite3.connect(DB_PATH)


def ensure(conn: sqlite3.Connection) -> None:
    conn.execute(
        "CREATE TABLE IF NOT EXISTS articles ("
        "id TEXT PRIMARY KEY, title TEXT NOT NULL, body TEXT NOT NULL)"
    )
    count = conn.execute("SELECT COUNT(*) FROM articles").fetchone()
    if count is not None and count[0]:
        return
    conn.execute(
        "INSERT INTO articles (id, title, body) VALUES (?, ?, ?)",
        ("a1", "Dock notes", "north door"),
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
    prefix = "/articles/"
    if method != "GET" or not path.startswith(prefix) or path == prefix:
        return _json(start_response, "404 Not Found", {"error": "not found"})
    article_id = path[len(prefix) :]
    conn = connect()
    try:
        ensure(conn)
        row = conn.execute(
            "SELECT title, body FROM articles WHERE id = ? LIMIT 1",
            (article_id,),
        ).fetchone()
        if row is None:
            return _json(start_response, "404 Not Found", {"error": "not found"})
        try:
            conn.execute("INSERT INTO views (article_id) VALUES (?)", (article_id,))
            conn.commit()
        except sqlite3.Error:
            logging.exception("view counter failed")
        payload = {"id": article_id, "title": row[0], "body": row[1]}
    finally:
        conn.close()
    return _json(start_response, "200 OK", payload)


app = application
