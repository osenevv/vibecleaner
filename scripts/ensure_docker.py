#!/usr/bin/env python3
"""Publish the Colima socket on localhost so a sandboxed shell can run Docker.

The sandbox refuses the Unix socket at ~/.colima/default/docker.sock. This
process opens that socket itself and forwards 127.0.0.1:2375 to it. Run it
outside the sandbox. It prints a DOCKER_HOST line and keeps running.
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import sys
import threading
from pathlib import Path

PORT = 2375


def main() -> int:
    if _tcp_ok():
        _announce()
        return 0
    sock_path = Path.home() / ".colima" / "default" / "docker.sock"
    if not sock_path.exists():
        if shutil.which("colima") is None:
            print("colima is not installed and the Docker socket is missing", file=sys.stderr)
            return 1
        subprocess.run(["colima", "start"], check=True)
    if not sock_path.exists():
        print(f"Docker socket still missing: {sock_path}", file=sys.stderr)
        return 1
    _serve(sock_path)
    return 0


def _tcp_ok() -> bool:
    try:
        probe = socket.create_connection(("127.0.0.1", PORT), timeout=0.5)
    except OSError:
        return False
    probe.close()
    return _docker_ok(f"tcp://127.0.0.1:{PORT}")


def _docker_ok(host: str) -> bool:
    if shutil.which("docker") is None:
        return False
    env = os.environ.copy()
    env["DOCKER_HOST"] = host
    proc = subprocess.run(["docker", "info"], env=env, capture_output=True, check=False)
    return proc.returncode == 0


def _announce() -> None:
    print(f"DOCKER_HOST=tcp://127.0.0.1:{PORT}")


def _serve(sock_path: Path) -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", PORT))
    server.listen(16)
    _announce()
    sys.stdout.flush()
    while True:
        client, _addr = server.accept()
        threading.Thread(target=_bridge, args=(client, sock_path), daemon=True).start()


def _bridge(client: socket.socket, sock_path: Path) -> None:
    remote = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        remote.connect(str(sock_path))
    except OSError:
        client.close()
        remote.close()
        return
    threads = [
        threading.Thread(target=_pump, args=(client, remote), daemon=True),
        threading.Thread(target=_pump, args=(remote, client), daemon=True),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    client.close()
    remote.close()


def _pump(source: socket.socket, dest: socket.socket) -> None:
    try:
        while True:
            chunk = source.recv(65536)
            if not chunk:
                break
            dest.sendall(chunk)
    except OSError:
        pass
    finally:
        try:
            dest.shutdown(socket.SHUT_WR)
        except OSError:
            pass


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, subprocess.CalledProcessError) as exc:
        print(f"ensure_docker: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
