"""Money-path / critical-flow verification runner (``.vibecleaner/flows.json``)."""

from __future__ import annotations

import json
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from vibecleaner.agents.transport import Unreachable, body_text, fetch
from vibecleaner.fix_contract import CheckResult, Evidence, EvidenceKind, ProviderError, Verdict
from vibecleaner.verify.sandbox import HostSandbox

FLOWS_VERSION = 1
DEFAULT_FLOWS_REL = ".vibecleaner/flows.json"
DEFAULT_TIMEOUT_S = 20.0


class FlowsError(ValueError):
    """Raised when ``.vibecleaner/flows.json`` is invalid."""


@dataclass(frozen=True)
class FlowSpec:
    name: str
    kind: str  # "command" | "http"
    command: tuple[str, ...] = ()
    url: str = ""
    method: str = "GET"
    expect_exit: int = 0
    expect_status: int = 200
    expect_output: tuple[str, ...] = ()
    forbid_output: tuple[str, ...] = ()
    timeout_s: float = DEFAULT_TIMEOUT_S


@dataclass(frozen=True)
class FlowResult:
    name: str
    kind: str
    ok: bool
    duration_s: float
    detail: str
    output: str = ""
    command: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "kind": self.kind,
            "ok": self.ok,
            "duration_s": round(self.duration_s, 3),
            "detail": self.detail,
        }


@dataclass(frozen=True)
class FlowReport:
    root: Path
    results: tuple[FlowResult, ...]

    @property
    def passed(self) -> int:
        return sum(1 for r in self.results if r.ok)

    @property
    def failed(self) -> int:
        return sum(1 for r in self.results if not r.ok)

    @property
    def ok(self) -> bool:
        return self.failed == 0

    def to_dict(self) -> dict[str, object]:
        return {
            "root": str(self.root),
            "ok": self.ok,
            "passed": self.passed,
            "failed": self.failed,
            "results": [r.to_dict() for r in self.results],
        }


def load_flows(root: Path, path: Path | None = None) -> tuple[FlowSpec, ...]:
    """Load and validate ``.vibecleaner/flows.json``. Returns ``()`` when absent."""
    resolved = Path(path) if path is not None else Path(root) / DEFAULT_FLOWS_REL
    if not resolved.is_file():
        if path is not None:
            raise FlowsError(f"flows file not found: {resolved}")
        return ()
    try:
        raw = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FlowsError(f"invalid flows file {resolved}: {exc}") from exc
    if not isinstance(raw, dict) or raw.get("version") != FLOWS_VERSION:
        raise FlowsError(f"invalid flows version in {resolved}: expected {FLOWS_VERSION}")
    items = raw.get("flows")
    if not isinstance(items, list):
        raise FlowsError(f"'flows' must be a list in {resolved}")
    specs: list[FlowSpec] = []
    for idx, item in enumerate(items):
        specs.append(_parse_flow(item, idx, resolved))
    return tuple(specs)


def _parse_flow(item: object, idx: int, source: Path) -> FlowSpec:
    if not isinstance(item, dict):
        raise FlowsError(f"flow[{idx}] in {source} must be an object")
    name = item.get("name")
    kind = item.get("kind")
    if not isinstance(name, str) or not name.strip():
        raise FlowsError(f"flow[{idx}] in {source} missing non-empty 'name'")
    if kind not in {"command", "http"}:
        raise FlowsError(f"flow '{name}' in {source} has unsupported kind {kind!r} (expected 'command' or 'http')")
    timeout = item.get("timeout_s", DEFAULT_TIMEOUT_S)
    if not isinstance(timeout, (int, float)) or timeout <= 0 or timeout > 300:
        raise FlowsError(f"flow '{name}' has invalid timeout_s (must be 0 < t <= 300)")

    expect_out = _str_tuple(item.get("expect_stdout", item.get("expect_body", [])), "expect", name)
    forbid_out = _str_tuple(item.get("forbid_stdout", item.get("forbid_body", [])), "forbid", name)

    if kind == "command":
        cmd = item.get("command")
        if not isinstance(cmd, list) or not cmd or not all(isinstance(part, str) and part for part in cmd):
            raise FlowsError(f"command flow '{name}' requires non-empty string list 'command'")
        expect_exit = item.get("expect_exit", 0)
        if not isinstance(expect_exit, int):
            raise FlowsError(f"command flow '{name}' requires integer 'expect_exit'")
        return FlowSpec(
            name=name.strip(),
            kind="command",
            command=tuple(cmd),
            expect_exit=expect_exit,
            expect_output=expect_out,
            forbid_output=forbid_out,
            timeout_s=float(timeout),
        )

    url = item.get("url")
    if not isinstance(url, str) or not url.startswith(("http://", "https://")):
        raise FlowsError(f"http flow '{name}' requires http(s) 'url'")
    method = str(item.get("method", "GET")).upper()
    expect_status = item.get("expect_status", 200)
    if not isinstance(expect_status, int):
        raise FlowsError(f"http flow '{name}' requires integer 'expect_status'")
    return FlowSpec(
        name=name.strip(),
        kind="http",
        url=url,
        method=method,
        expect_status=expect_status,
        expect_output=expect_out,
        forbid_output=forbid_out,
        timeout_s=float(timeout),
    )


def _str_tuple(value: object, field: str, flow_name: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
        raise FlowsError(f"flow '{flow_name}' field '{field}' must be a list of strings")
    return tuple(value)


def run_flows(root: Path, flows: Sequence[FlowSpec]) -> FlowReport:
    """Execute each money-path flow and verify its expected exit/status and output invariants."""
    resolved = Path(root).expanduser().resolve()
    sandbox = HostSandbox(resolved)
    results = [_run_one(sandbox, resolved, flow) for flow in flows]
    return FlowReport(root=resolved, results=tuple(results))


def _run_one(sandbox: HostSandbox, root: Path, flow: FlowSpec) -> FlowResult:
    if flow.kind == "command":
        res = sandbox.run(flow.command, cwd=root, timeout_s=flow.timeout_s)
        combined = "\n".join(p for p in (res.stdout, res.stderr) if p).strip()
        if res.timed_out:
            return FlowResult(flow.name, "command", False, res.duration_s, f"timed out after {flow.timeout_s}s", combined, flow.command)
        if res.returncode != flow.expect_exit:
            return FlowResult(
                flow.name,
                "command",
                False,
                res.duration_s,
                f"expected exit {flow.expect_exit}, got {res.returncode}",
                combined,
                flow.command,
            )
        mismatch = _check_output(combined, flow.expect_output, flow.forbid_output)
        if mismatch:
            return FlowResult(flow.name, "command", False, res.duration_s, mismatch, combined, flow.command)
        return FlowResult(flow.name, "command", True, res.duration_s, f"exit {res.returncode} matched", combined, flow.command)

    curl_cmd = ("curl", "-sS", "-X", flow.method, flow.url)
    started = time.perf_counter()
    try:
        status, raw_body = fetch(flow.method, flow.url, timeout_s=flow.timeout_s, local=False)
    except (Unreachable, ProviderError) as exc:
        return FlowResult(flow.name, "http", False, time.perf_counter() - started, str(exc), "", curl_cmd)
    elapsed = time.perf_counter() - started
    text = body_text(raw_body, limit=4000)
    if status != flow.expect_status:
        return FlowResult(flow.name, "http", False, elapsed, f"expected HTTP {flow.expect_status}, got {status}", text, curl_cmd)
    mismatch = _check_output(text, flow.expect_output, flow.forbid_output)
    if mismatch:
        return FlowResult(flow.name, "http", False, elapsed, mismatch, text, curl_cmd)
    return FlowResult(flow.name, "http", True, elapsed, f"HTTP {status} matched", text, curl_cmd)


def _check_output(text: str, expected: tuple[str, ...], forbidden: tuple[str, ...]) -> str | None:
    for needle in expected:
        if needle not in text:
            return f"missing expected output {needle!r}"
    for needle in forbidden:
        if needle in text:
            return f"found forbidden output {needle!r}"
    return None


def to_check_result(report: FlowReport) -> CheckResult:
    """Adapt a ``FlowReport`` into a ``CheckResult`` gate for ``vibecleaner start``."""
    if report.ok:
        return CheckResult("flows", Verdict.PASS)
    evidence = tuple(
        Evidence(
            kind=EvidenceKind.TEST_FAILURE,
            summary=f"flow '{item.name}' failed: {item.detail}",
            command=item.command or ("vibecleaner", "flows"),
            output=item.output or item.detail,
        )
        for item in report.results
        if not item.ok
    )
    return CheckResult("flows", Verdict.REVISE, evidence=evidence)
