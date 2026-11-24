"""Runtime check. Boots a detected HTTP server on a free port and probes malformed input."""

from __future__ import annotations

import http.client
import shutil
import socket
import subprocess
import time
from pathlib import Path

from vibecleaner.fix_contract import CheckResult, Evidence, EvidenceKind, FixContext, Verdict
from vibecleaner.runtime.detect import detect_app

_BOOT_TIMEOUT_S = 3.0
_POLL_INTERVAL_S = 0.05


def runtime_check(ctx: FixContext, cwd: Path) -> CheckResult:
    """Skip libraries; boot a detected server on localhost and send one malformed request."""
    root = Path(cwd)
    spec = detect_app(root)
    if spec is None:
        return CheckResult(
            "runtime",
            Verdict.PASS,
            notes=(Evidence(EvidenceKind.JUDGE_NOTE, "No web app to boot."),),
        )
    port = _free_port()
    argv = list(spec.command(port))
    command = " ".join(argv)
    resolved = shutil.which(argv[0]) if argv else None
    if ctx.sandbox.name != "host" or resolved is None:
        return CheckResult(
            "runtime",
            Verdict.ESCALATE,
            notes=(
                Evidence(
                    EvidenceKind.JUDGE_NOTE,
                    f"A {spec.kind} app was detected and was not booted. Command: {command}",
                ),
            ),
        )
    argv[0] = resolved
    try:
        proc = subprocess.Popen(
            argv,
            cwd=root,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
            text=True,
            errors="replace",
        )
    except OSError:
        return CheckResult(
            "runtime",
            Verdict.ESCALATE,
            notes=(
                Evidence(
                    EvidenceKind.JUDGE_NOTE,
                    f"A {spec.kind} app was detected and could not be started. Command: {command}",
                ),
            ),
        )
    try:
        ready = _wait_port(port, proc, _BOOT_TIMEOUT_S)
        if not ready:
            return CheckResult(
                "runtime",
                Verdict.ESCALATE,
                notes=(
                    Evidence(
                        EvidenceKind.JUDGE_NOTE,
                        f"A {spec.kind} app was detected and did not open port {port}. Command: {command}",
                    ),
                ),
            )
        status = _probe_malformed(port)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=2)
    if status >= 500:
        return CheckResult(
            "runtime",
            Verdict.REVISE,
            evidence=(
                Evidence(
                    EvidenceKind.RUNTIME_CRASH,
                    f"{spec.kind} returned HTTP {status} on malformed JSON POST /",
                    command=tuple(argv),
                ),
            ),
        )
    return CheckResult(
        "runtime",
        Verdict.PASS,
        notes=(
            Evidence(
                EvidenceKind.JUDGE_NOTE,
                f"Booted {spec.kind} on port {port}; malformed JSON POST / returned HTTP {status}.",
            ),
        ),
    )


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_port(port: int, proc: subprocess.Popen[str], timeout_s: float) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            return False
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                return True
        except OSError:
            time.sleep(_POLL_INTERVAL_S)
    return False


def _probe_malformed(port: int) -> int:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2.0)
    try:
        conn.request("POST", "/", body='{"bad":', headers={"Content-Type": "application/json"})
        resp = conn.getresponse()
        resp.read()
        return resp.status
    except OSError:
        return 500
    finally:
        conn.close()
