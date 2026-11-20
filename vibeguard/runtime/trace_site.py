"""Process-wide SQL and request trace. Installed only when VIBEGUARD_TRACE is set."""

from __future__ import annotations

import importlib.machinery
import json
import logging
import os
import sqlite3
import sys
import threading
import time

_local = threading.local()
_PATCHES: dict[str, object] = {}


def install() -> None:
    _patch_sqlite()
    _patch_logging()
    _patch_wsgi()
    if not any(isinstance(finder, _Finder) for finder in sys.meta_path):
        sys.meta_path.insert(0, _Finder())
    for name, patch in _PATCHES.items():
        module = sys.modules.get(name)
        if module is not None:
            patch(module)


def _request(method: str, path: str) -> dict:
    return {
        "method": method.upper(),
        "path": path or "/",
        "status": 0,
        "duration_ms": 0,
        "queries": [],
        "exceptions": [],
        "_done": False,
    }


def _note_query(statement: str) -> None:
    record = getattr(_local, "req", None)
    if record is None:
        return
    text = statement.strip()
    if text:
        record["queries"].append(text[:2000])


def _note_exception(message: str) -> None:
    record = getattr(_local, "req", None)
    if record is None or not message:
        return
    record["exceptions"].append(message[:500])


def _finish(record: dict, started: float) -> None:
    if record.get("_done"):
        return
    record["_done"] = True
    record["duration_ms"] = round((time.perf_counter() - started) * 1000, 3)
    _emit(
        {
            "method": record["method"],
            "path": record["path"],
            "status": record["status"],
            "duration_ms": record["duration_ms"],
            "queries": record["queries"],
            "exceptions": record["exceptions"],
        }
    )


def _clear() -> None:
    _local.req = None
    _local.depth = 0


def _emit(record: dict) -> None:
    path = os.environ.get("VIBEGUARD_TRACE")
    if not path:
        return
    try:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, separators=(",", ":")) + "\n")
    except OSError:
        return


class _ErrorTap(logging.Handler):
    def emit(self, record: logging.LogRecord) -> None:
        if record.levelno < logging.ERROR:
            return
        try:
            message = record.getMessage()
        except (TypeError, ValueError):
            message = str(record.msg)
        _note_exception(message)


def _patch_logging() -> None:
    root = logging.getLogger()
    if any(getattr(handler, "_vibeguard", False) for handler in root.handlers):
        return
    handler = _ErrorTap()
    setattr(handler, "_vibeguard", True)
    root.addHandler(handler)


def _patch_sqlite() -> None:
    original = sqlite3.connect
    if getattr(original, "_vibeguard", False):
        return

    def connect(*args, **kwargs):
        connection = original(*args, **kwargs)
        try:
            connection.set_trace_callback(_note_query)
        except sqlite3.Error:
            return connection
        return connection

    setattr(connect, "_vibeguard", True)
    sqlite3.connect = connect


def _capture_status(start_response, record: dict):
    def start(status, headers, exc_info=None):
        try:
            record["status"] = int(str(status).split()[0])
        except (TypeError, ValueError):
            record["status"] = 0
        return start_response(status, headers, exc_info)

    return start


def _serve_wsgi(application, environ, start_response):
    if getattr(_local, "depth", 0):
        return application(environ, start_response)
    record = _request(environ.get("REQUEST_METHOD", ""), environ.get("PATH_INFO", "/") or "/")
    _local.depth = 1
    _local.req = record
    started = time.perf_counter()
    try:
        result = application(environ, _capture_status(start_response, record))
    except Exception as exc:
        _note_exception(f"{type(exc).__name__}: {exc}")
        _finish(record, started)
        _clear()
        raise
    return _Closing(result, record, started)


class _Closing:
    def __init__(self, result, record: dict, started: float) -> None:
        self._result = result
        self._record = record
        self._started = started
        self._iterator = None
        self._closed = False

    def __iter__(self):
        self._iterator = iter(self._result)
        return self

    def __next__(self):
        if self._iterator is None:
            self._iterator = iter(self._result)
        return next(self._iterator)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        closer = getattr(self._result, "close", None)
        if closer is not None:
            closer()
        _finish(self._record, self._started)
        _clear()


def _patch_wsgi() -> None:
    import wsgiref.handlers

    original = wsgiref.handlers.BaseHandler.run
    if getattr(original, "_vibeguard", False):
        return

    def run(self, application):
        def wrapped(environ, start_response):
            return _serve_wsgi(application, environ, start_response)

        return original(self, wrapped)

    setattr(run, "_vibeguard", True)
    wsgiref.handlers.BaseHandler.run = run


async def _serve_asgi(original, self, scope, receive, send):
    if getattr(_local, "depth", 0):
        await original(self, scope, receive, send)
        return
    record = _request(scope.get("method", ""), scope.get("path", "/") or "/")
    _local.depth = 1
    _local.req = record
    started = time.perf_counter()

    async def send_wrap(message):
        if message.get("type") == "http.response.start":
            try:
                record["status"] = int(message.get("status") or 0)
            except (TypeError, ValueError):
                record["status"] = 0
        await send(message)

    try:
        await original(self, scope, receive, send_wrap)
    except Exception as exc:
        _note_exception(f"{type(exc).__name__}: {exc}")
        raise
    finally:
        _finish(record, started)
        _clear()


def _patch_flask(module) -> None:
    flask_cls = getattr(module, "Flask", None)
    if flask_cls is None:
        return
    original = flask_cls.__call__
    if getattr(original, "_vibeguard", False):
        return

    def call(self, environ, start_response):
        def inner(env, start):
            return original(self, env, start)

        return _serve_wsgi(inner, environ, start_response)

    setattr(call, "_vibeguard", True)
    flask_cls.__call__ = call


def _patch_starlette(module) -> None:
    starlette_cls = getattr(module, "Starlette", None)
    if starlette_cls is None:
        return
    original = starlette_cls.__call__
    if getattr(original, "_vibeguard", False):
        return

    async def call(self, scope, receive, send):
        if scope.get("type") != "http":
            await original(self, scope, receive, send)
            return
        await _serve_asgi(original, self, scope, receive, send)

    setattr(call, "_vibeguard", True)
    starlette_cls.__call__ = call


def _patch_fastapi(module) -> None:
    loaded = sys.modules.get("starlette.applications")
    if loaded is not None:
        _patch_starlette(loaded)


def _patch_sqlalchemy(module) -> None:
    if getattr(_patch_sqlalchemy, "_done", False):
        return
    try:
        from sqlalchemy import event
        from sqlalchemy.engine import Engine
    except ImportError:
        return

    def listen(conn, cursor, statement, parameters, context, executemany):
        dialect = getattr(getattr(conn, "engine", None), "dialect", None)
        if getattr(dialect, "name", "") == "sqlite":
            return
        if isinstance(statement, str):
            _note_query(statement)

    event.listens_for(Engine, "before_cursor_execute")(listen)
    setattr(_patch_sqlalchemy, "_done", True)


def _wrap_cursor(cursor) -> None:
    original = getattr(cursor, "execute", None)
    if original is None or getattr(original, "_vibeguard", False):
        return

    def execute(query, *args, **kwargs):
        if isinstance(query, str):
            _note_query(query)
        else:
            as_string = getattr(query, "as_string", None)
            if as_string is not None:
                try:
                    _note_query(as_string(cursor))
                except (TypeError, ValueError):
                    _note_query(str(query))
        return original(query, *args, **kwargs)

    setattr(execute, "_vibeguard", True)
    cursor.execute = execute


def _patch_psycopg(module) -> None:
    original = getattr(module, "connect", None)
    if original is None or getattr(original, "_vibeguard", False):
        return

    def connect(*args, **kwargs):
        connection = original(*args, **kwargs)
        cursor_factory = getattr(connection, "cursor", None)
        if cursor_factory is None:
            return connection

        def cursor(*cargs, **ckwargs):
            made = cursor_factory(*cargs, **ckwargs)
            _wrap_cursor(made)
            return made

        connection.cursor = cursor
        return connection

    setattr(connect, "_vibeguard", True)
    module.connect = connect


def _patch_psycopg2(module) -> None:
    _patch_psycopg(module)


class _PatchLoader:
    def __init__(self, inner, patch) -> None:
        self._inner = inner
        self._patch = patch

    def create_module(self, spec):
        create = getattr(self._inner, "create_module", None)
        if create is None:
            return None
        return create(spec)

    def __getattr__(self, name):
        return getattr(self._inner, name)

    def exec_module(self, module) -> None:
        self._inner.exec_module(module)
        try:
            self._patch(module)
        except (AttributeError, ImportError, TypeError, ValueError):
            return


class _Finder:
    def find_spec(self, fullname, path, target=None):
        patch = _PATCHES.get(fullname)
        if patch is None or getattr(_local, "finding", False):
            return None
        _local.finding = True
        try:
            spec = importlib.machinery.PathFinder.find_spec(fullname, path)
        finally:
            _local.finding = False
        if spec is None or spec.loader is None:
            return None
        spec.loader = _PatchLoader(spec.loader, patch)
        return spec


_PATCHES.update(
    {
        "flask": _patch_flask,
        "fastapi": _patch_fastapi,
        "starlette.applications": _patch_starlette,
        "sqlalchemy": _patch_sqlalchemy,
        "sqlalchemy.engine": _patch_sqlalchemy,
        "psycopg": _patch_psycopg,
        "psycopg2": _patch_psycopg2,
    }
)


if os.environ.get("VIBEGUARD_TRACE"):
    install()
