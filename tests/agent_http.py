"""Local OpenAI-compatible server for agent tests."""

from __future__ import annotations

import json
import math
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit


class Bench:
    def __init__(self, models: list[dict], *, show: dict | None = None, mode: str = "text") -> None:
        self.models = models
        self.show = show
        self.mode = mode
        self.seen: list[dict] = []


class _Server(ThreadingHTTPServer):
    allow_reuse_address = True
    bench: Bench


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args) -> None:
        return

    def do_GET(self) -> None:
        path = urlsplit(self.path).path.rstrip("/")
        if path == "/v1/models":
            self._send(200, {"object": "list", "data": self.server.bench.models})
            return
        self._send(404, {"error": "not found"})

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0") or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            body = json.loads(raw.decode("utf-8")) if raw else {}
        except json.JSONDecodeError:
            body = {}
        path = urlsplit(self.path).path.rstrip("/")
        self.server.bench.seen.append(
            {
                "path": path,
                "body": body,
                "authorization": self.headers.get("Authorization"),
            }
        )
        if path == "/api/show":
            if self.server.bench.show is None:
                self._send(404, {"error": "no show"})
                return
            self._send(200, self.server.bench.show)
            return
        if path == "/v1/messages":
            text = body.get("messages", [{}])[-1].get("content", "")
            self._send(200, {"content": [{"type": "text", "text": f"anthropic:{text}"}]})
            return
        if path != "/v1/chat/completions":
            self._send(404, {"error": "not found"})
            return
        mode = self.server.bench.mode
        if mode == "error":
            self._send(500, {"error": "boom"})
            return
        if body.get("logprobs") and mode == "reject-logprobs":
            self._send(400, {"error": {"message": "logprobs is not supported"}})
            return
        if body.get("logprobs"):
            prompt = body["messages"][-1]["content"]
            if "UNSAFE" in prompt:
                self._send(200, _logprobs("no", math.log(0.2), math.log(0.8)))
            elif mode == "maybe":
                self._send(200, _logprobs("maybe", math.log(0.5), math.log(0.5)))
            else:
                self._send(200, _logprobs("yes", math.log(0.9), math.log(0.1)))
            return
        self._send(200, {"choices": [{"message": {"role": "assistant", "content": "patched"}}]})

    def _send(self, status: int, payload: dict) -> None:
        raw = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


def _logprobs(token: str, yes_lp: float, no_lp: float) -> dict:
    chosen = yes_lp if token == "yes" else no_lp
    top = [{"token": "yes", "logprob": yes_lp}, {"token": "no", "logprob": no_lp}]
    if token == "maybe":
        top = [{"token": "maybe", "logprob": yes_lp}]
        chosen = yes_lp
    return {
        "choices": [
            {
                "message": {"role": "assistant", "content": token},
                "logprobs": {"content": [{"token": token, "logprob": chosen, "top_logprobs": top}]},
            }
        ]
    }


@contextmanager
def serve(bench: Bench, port: int = 0):
    httpd = _Server(("127.0.0.1", port), Handler)
    httpd.bench = bench
    thread = threading.Thread(target=httpd.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    try:
        yield httpd
    finally:
        httpd.shutdown()
        httpd.server_close()


def base_url(httpd: _Server) -> str:
    return f"http://127.0.0.1:{httpd.server_address[1]}"
