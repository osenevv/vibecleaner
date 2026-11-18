from __future__ import annotations

import json


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
    if method != "POST" or environ.get("PATH_INFO") != "/bookings":
        return _json(start_response, "404 Not Found", {"error": "not found"})
    payload = json.loads(_body(environ))
    name = payload.get("name") if isinstance(payload, dict) else None
    if not isinstance(name, str) or not name.strip():
        return _json(start_response, "400 Bad Request", {"error": "name required"})
    return _json(start_response, "201 Created", {"name": name.strip()})


app = application
