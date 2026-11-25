"""Tests for async specialist jury fan-out, timeout isolation, and scratch-dir cleanup."""

from __future__ import annotations

import asyncio
import json
import threading
from pathlib import Path

import pytest

from vibecleaner.fix_contract import (
    Capabilities,
    EvidenceKind,
    ExecResult,
    FixContext,
    ProviderError,
    Team,
    Verdict,
)
from vibecleaner.jury.asking import HostJudge, complete_first_async
from vibecleaner.jury.panel import SPECIALISTS, run_panel, run_panel_async
from vibecleaner.verify.sandbox import HostSandbox


class _BarrierProvider:
    """Proves true concurrent execution without fixed sleeps via threading.Barrier."""

    def __init__(self, barrier_size: int) -> None:
        self.name = "barrier-judge"
        self.family = "test"
        self.local = True
        self.capabilities = Capabilities(context_tokens=16_000)
        self._barrier = threading.Barrier(barrier_size, timeout=5.0)
        self._lock = threading.Lock()
        self.active = 0
        self.peak = 0
        self.calls = 0

    def complete(self, system: str, prompt: str, *, json_mode: bool = False) -> str:
        del system, prompt, json_mode
        with self._lock:
            self.active += 1
            self.calls += 1
            self.peak = max(self.peak, self.active)
        try:
            self._barrier.wait()
            return json.dumps({"findings": []})
        finally:
            with self._lock:
                self.active -= 1

    def yes_probability(self, system: str, prompt: str) -> float | None:
        del system, prompt
        return None


class _TimeoutAndProbeProvider:
    """Hangs on one specialist while returning a failing probe on another."""

    def __init__(self, release: threading.Event) -> None:
        self.name = "mixed-judge"
        self.family = "test"
        self.local = True
        self.capabilities = Capabilities(context_tokens=16_000)
        self._release = release
        self.completed_titles: list[str] = []

    def complete(self, system: str, prompt: str, *, json_mode: bool = False) -> str:
        del prompt, json_mode
        if "concurrency and races" in system:
            # Block until timeout fires (released in test finally block).
            self._release.wait(timeout=5.0)
            return json.dumps({"findings": []})
        self.completed_titles.append(system)
        if "edge cases" in system:
            return json.dumps(
                {
                    "findings": [
                        {
                            "file": "app.py",
                            "line": 1,
                            "function": "calc",
                            "problem": "edge case breaks on zero",
                            "probe": "assert 1 == 2",
                        }
                    ]
                }
            )
        return json.dumps(
            {
                "findings": [
                    {
                        "file": "app.py",
                        "line": 1,
                        "function": "calc",
                        "problem": "advisory note only",
                    }
                ]
            }
        )

    def yes_probability(self, system: str, prompt: str) -> float | None:
        del system, prompt
        return None


class _MultiProbeProvider:
    """Returns a failing pytest probe for every specialist to test probe filename isolation."""

    name = "multi-probe-judge"
    family = "test"
    local = True
    capabilities = Capabilities(context_tokens=16_000)

    def complete(self, system: str, prompt: str, *, json_mode: bool = False) -> str:
        del prompt, json_mode
        label = system.split("for ", 1)[1].split(".", 1)[0]
        return json.dumps(
            {
                "findings": [
                    {
                        "file": "app.py",
                        "line": 1,
                        "problem": f"issue in {label}",
                        "probe": f"assert False, {label!r}",
                    }
                ]
            }
        )

    def yes_probability(self, system: str, prompt: str) -> float | None:
        del system, prompt
        return None


class _BlockingHost:
    """Host that records created scratch dirs and blocks on an Event until released."""

    name = "blocking-host"
    family = "host"

    def __init__(self, started: threading.Event, release: threading.Event, *, write_answer: str | None = None) -> None:
        self._started = started
        self._release = release
        self._write_answer = write_answer
        self.scratch_dirs: list[Path] = []

    def run_task(self, worktree: Path, instructions: str, *, timeout_s: float) -> ExecResult:
        del instructions, timeout_s
        self.scratch_dirs.append(worktree)
        self._started.set()
        self._release.wait(timeout=5.0)
        if self._write_answer is not None and worktree.is_dir():
            (worktree / "answer.json").write_text(self._write_answer, encoding="utf-8")
        return ExecResult(("host",), 0, "", "", 0.01)


class _SimpleProvider:
    def __init__(self, name: str, reply: str | None = None, *, error: str | None = None) -> None:
        self.name = name
        self.family = "test"
        self.local = True
        self.capabilities = Capabilities(context_tokens=16_000)
        self._reply = reply
        self._error = error

    def complete(self, system: str, prompt: str, *, json_mode: bool = False) -> str:
        del system, prompt, json_mode
        if self._error is not None:
            raise ProviderError(self._error)
        return self._reply or ""

    def yes_probability(self, system: str, prompt: str) -> float | None:
        del system, prompt
        return None


def _ctx(root: Path, team: Team) -> FixContext:
    return FixContext(root=root, sandbox=HostSandbox(root), team=team)


def test_run_panel_async_executes_all_4_specialists_concurrently(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("def calc(x: int) -> int:\n    return x + 1\n", encoding="utf-8")
    provider = _BarrierProvider(barrier_size=len(SPECIALISTS))
    ctx = _ctx(tmp_path, Team(host=None, providers=(provider,)))

    result = asyncio.run(run_panel_async(ctx, {"app.py": frozenset({1, 2})}, max_concurrency=4))
    assert result.verdict is Verdict.PASS
    assert provider.calls == 4
    assert provider.peak == 4


def test_run_panel_async_respects_semaphore_limit(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("def calc(x: int) -> int:\n    return x + 1\n", encoding="utf-8")
    provider = _BarrierProvider(barrier_size=2)
    ctx = _ctx(tmp_path, Team(host=None, providers=(provider,)))

    result = asyncio.run(run_panel_async(ctx, {"app.py": frozenset({1, 2})}, max_concurrency=2))
    assert result.verdict is Verdict.PASS
    assert provider.calls == 4
    assert provider.peak == 2


def test_single_specialist_timeout_does_not_hang_other_three(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("def calc(x: int) -> int:\n    return x + 1\n", encoding="utf-8")
    release = threading.Event()
    provider = _TimeoutAndProbeProvider(release)
    ctx = _ctx(tmp_path, Team(host=None, providers=(provider,)))
    try:
        result = run_panel(ctx, {"app.py": frozenset({1, 2})}, timeout_s=0.15)
    finally:
        release.set()

    assert len(provider.completed_titles) == 3
    assert result.verdict is Verdict.REVISE
    assert len(result.evidence) == 1
    assert result.evidence[0].kind is EvidenceKind.TEST_FAILURE
    assert "edge case breaks on zero" in result.evidence[0].summary
    assert len(result.notes) == 2


def test_concurrent_probes_do_not_collide_on_disk(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("def calc(x: int) -> int:\n    return x + 1\n", encoding="utf-8")
    ctx = _ctx(tmp_path, Team(host=None, providers=(_MultiProbeProvider(),)))

    result = run_panel(ctx, {"app.py": frozenset({1, 2})})
    assert result.verdict is Verdict.REVISE
    assert len(result.evidence) == len(SPECIALISTS)
    jury_dir = tmp_path / ".vibecleaner" / "jury"
    probe_files = sorted(p.name for p in jury_dir.glob("probe_*.py"))
    assert len(probe_files) == len(SPECIALISTS)


def test_host_judge_complete_async_cleans_scratch_on_cancel_and_timeout() -> None:
    # 1. Cancellation cleanup
    started_cancel = threading.Event()
    release_cancel = threading.Event()
    host_cancel = _BlockingHost(started_cancel, release_cancel)
    judge_cancel = HostJudge(host_cancel)

    async def _run_cancel() -> None:
        task = asyncio.create_task(judge_cancel.complete_async("sys", "prompt", timeout_s=5.0))
        while not started_cancel.is_set():
            await asyncio.to_thread(started_cancel.wait, 0.05)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    try:
        asyncio.run(_run_cancel())
    finally:
        release_cancel.set()

    assert len(host_cancel.scratch_dirs) == 1
    assert not host_cancel.scratch_dirs[0].exists()

    # 2. Timeout cleanup
    started_to = threading.Event()
    release_to = threading.Event()
    host_to = _BlockingHost(started_to, release_to)
    judge_to = HostJudge(host_to)

    try:
        with pytest.raises(ProviderError, match="timed out"):
            asyncio.run(judge_to.complete_async("sys", "prompt", timeout_s=0.1))
    finally:
        release_to.set()

    assert len(host_to.scratch_dirs) == 1
    assert not host_to.scratch_dirs[0].exists()

    # 3. Normal completion reads answer.json and cleans scratch
    started_ok = threading.Event()
    release_ok = threading.Event()
    release_ok.set()
    host_ok = _BlockingHost(started_ok, release_ok, write_answer='{"findings": []}')
    judge_ok = HostJudge(host_ok)
    reply = asyncio.run(judge_ok.complete_async("sys", "prompt", timeout_s=5.0))
    assert reply == '{"findings": []}'
    assert not host_ok.scratch_dirs[0].exists()


def test_complete_first_async_fallback_and_errors() -> None:
    with pytest.raises(ProviderError, match="no model is available"):
        asyncio.run(complete_first_async((), "sys", "prompt"))

    reply = asyncio.run(
        complete_first_async(
            (_SimpleProvider("first", error="rate limit"), _SimpleProvider("second", reply='{"ok": true}')),
            "sys",
            "prompt",
        )
    )
    assert reply == '{"ok": true}'

    with pytest.raises(ProviderError, match="first: boom; second: down"):
        asyncio.run(
            complete_first_async(
                (_SimpleProvider("first", error="boom"), _SimpleProvider("second", error="down")),
                "sys",
                "prompt",
            )
        )
