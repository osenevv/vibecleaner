"""Run project commands on the host or in a network-off container."""

from __future__ import annotations

import hashlib
import os
import subprocess
import tempfile
import time
import uuid
from collections.abc import Mapping, Sequence
from pathlib import Path

from vibecleaner.fix_contract import ExecResult, Sandbox, SandboxUnavailable
from vibecleaner.verify.files import project_runtimes

_PY_IMAGE = "python:3.12-slim"
_NODE_IMAGE = "node:22-slim"
_DOCKERFILE = (
    "FROM python:3.12-slim\n"
    "COPY --from=node:22-slim /usr/local/bin/node /usr/local/bin/node\n"
    "COPY --from=node:22-slim /usr/local/lib/node_modules /usr/local/lib/node_modules\n"
    "RUN ln -sf ../lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm"
    " && ln -sf ../lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx\n"
)
_KILL_TIMEOUT_S = 15


def make_sandbox(root: Path, kind: str = "docker") -> Sandbox:
    if kind == "host":
        return HostSandbox(root)
    if kind == "docker":
        return DockerSandbox(root)
    raise SandboxUnavailable(f"unknown sandbox kind {kind}")


def docker_unreachable_reason() -> str | None:
    try:
        completed = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
            check=False,
        )
    except FileNotFoundError:
        return "docker is not installed"
    except subprocess.TimeoutExpired:
        return "docker daemon is unreachable"
    if completed.returncode != 0:
        return "docker daemon is unreachable"
    return None


def choose_image(root: Path) -> str:
    runtimes = project_runtimes(root)
    if "python" in runtimes and "node" in runtimes:
        return combined_image_tag()
    if "node" in runtimes:
        return _NODE_IMAGE
    return _PY_IMAGE


def combined_image_tag() -> str:
    digest = hashlib.sha256(_DOCKERFILE.encode()).hexdigest()[:12]
    return f"vibecleaner-sandbox:{digest}"


class HostSandbox:
    """Run commands as host subprocesses. Opt-in for machines without Docker.

    ``network`` is accepted so callers share one signature with Docker. The host
    process is not isolated from the network.
    """

    name = "host"

    def __init__(self, root: Path) -> None:
        self.root = Path(root).resolve()

    def run(
        self,
        command: Sequence[str],
        *,
        cwd: Path,
        timeout_s: float,
        network: bool = False,
        env: Mapping[str, str] | None = None,
    ) -> ExecResult:
        del network
        workdir = _cwd_inside(self.root, cwd)
        merged = os.environ.copy()
        merged.setdefault("NO_COLOR", "1")
        if env:
            merged.update(env)
        return _run_subprocess(tuple(command), workdir, timeout_s, merged)


class DockerSandbox:
    """Run commands in a container with the project mounted at the same path.

    The container gets no host environment except ``env``. Network is off unless
    ``network`` is true. The process uid matches the host user.
    """

    name = "docker"

    def __init__(self, root: Path) -> None:
        reason = docker_unreachable_reason()
        if reason:
            raise SandboxUnavailable(reason)
        self.root = Path(root).resolve()

    @property
    def image(self) -> str:
        return choose_image(self.root)

    def run(
        self,
        command: Sequence[str],
        *,
        cwd: Path,
        timeout_s: float,
        network: bool = False,
        env: Mapping[str, str] | None = None,
    ) -> ExecResult:
        workdir = _cwd_inside(self.root, cwd)
        image = self.image
        try:
            _ensure_image(image)
        except SandboxUnavailable as exc:
            return ExecResult(tuple(command), 127, "", str(exc), 0.0, timed_out=False)
        container = f"vg-{uuid.uuid4().hex[:12]}"
        argv = _docker_argv(
            container=container,
            image=image,
            root=self.root,
            cwd=workdir,
            command=command,
            network=network,
            env=_container_env(env),
        )
        return _run_docker(tuple(command), argv, container, timeout_s)


def _container_env(env: Mapping[str, str] | None) -> dict[str, str]:
    merged = {"HOME": "/tmp", "NO_COLOR": "1", "PYTHONDONTWRITEBYTECODE": "1", "TERM": "dumb"}
    if env:
        merged.update({str(key): str(value) for key, value in env.items()})
    return merged


def _docker_argv(
    *,
    container: str,
    image: str,
    root: Path,
    cwd: Path,
    command: Sequence[str],
    network: bool,
    env: Mapping[str, str],
) -> list[str]:
    argv = [
        "docker",
        "run",
        "--name",
        container,
        "--rm",
        "--init",
        "--user",
        f"{os.getuid()}:{os.getgid()}",
        "--network",
        "bridge" if network else "none",
        "-v",
        f"{root}:{root}",
        "-w",
        str(cwd),
    ]
    for key, value in env.items():
        argv.extend(["-e", f"{key}={value}"])
    argv.append(image)
    argv.extend(command)
    return argv


def _ensure_image(image: str) -> None:
    if _image_present(image):
        return
    if image.startswith("vibecleaner-sandbox:"):
        _build_combined(image)
        return
    completed = subprocess.run(
        ["docker", "pull", image],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=300,
        check=False,
    )
    if completed.returncode != 0:
        raise SandboxUnavailable(f"could not pull {image}")


def _build_combined(tag: str) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        dockerfile = Path(tmp) / "Dockerfile"
        dockerfile.write_text(_DOCKERFILE, encoding="utf-8")
        completed = subprocess.run(
            ["docker", "build", "-t", tag, "-f", str(dockerfile), tmp],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=300,
            check=False,
        )
    if completed.returncode != 0:
        detail = _last_line(completed.stderr or completed.stdout)
        raise SandboxUnavailable(f"could not build the sandbox image: {detail}")


def _image_present(image: str) -> bool:
    completed = subprocess.run(
        ["docker", "image", "inspect", image],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    return completed.returncode == 0


def _run_docker(command: tuple[str, ...], argv: list[str], container: str, timeout_s: float) -> ExecResult:
    started = time.perf_counter()
    try:
        proc = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except FileNotFoundError:
        return ExecResult(command, 127, "", "docker is not installed", 0.0)
    except OSError as exc:
        return ExecResult(command, 127, "", str(exc), time.perf_counter() - started)
    try:
        stdout, stderr = proc.communicate(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        _kill_container(container)
        try:
            stdout, stderr = proc.communicate(timeout=_KILL_TIMEOUT_S)
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate()
        return ExecResult(
            command,
            proc.returncode if proc.returncode else 124,
            _text(stdout),
            _text(stderr),
            time.perf_counter() - started,
            timed_out=True,
        )
    return ExecResult(command, proc.returncode or 0, _text(stdout), _text(stderr), time.perf_counter() - started)


def _kill_container(container: str) -> None:
    try:
        subprocess.run(
            ["docker", "kill", container],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=_KILL_TIMEOUT_S,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return


def _run_subprocess(command: tuple[str, ...], cwd: Path, timeout_s: float, env: Mapping[str, str]) -> ExecResult:
    started = time.perf_counter()
    try:
        completed = subprocess.run(
            list(command),
            cwd=cwd,
            env=dict(env),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_s,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return ExecResult(
            command,
            124,
            _text(exc.stdout),
            _text(exc.stderr),
            time.perf_counter() - started,
            timed_out=True,
        )
    except FileNotFoundError as exc:
        return ExecResult(command, 127, "", str(exc), time.perf_counter() - started)
    except OSError as exc:
        return ExecResult(command, 127, "", str(exc), time.perf_counter() - started)
    return ExecResult(
        command,
        completed.returncode,
        completed.stdout,
        completed.stderr,
        time.perf_counter() - started,
    )


def _cwd_inside(root: Path, cwd: Path) -> Path:
    resolved = Path(cwd).resolve()
    base = root.resolve()
    if resolved != base and base not in resolved.parents:
        raise ValueError(f"cwd {resolved} is outside the sandbox root {base}")
    return resolved


def _text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _last_line(text: str) -> str:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    return lines[-1] if lines else "image build failed"
