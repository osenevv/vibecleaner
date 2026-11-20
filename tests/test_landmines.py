"""Testing and benchmark honesty guards based on the landmines rules."""

from __future__ import annotations

import ast
import importlib.util
import socket
import sys
from pathlib import Path

import pytest

from vibeguard.models import JudgeStats, ScanContext, ScanResult

_ROOT = Path(__file__).resolve().parents[1]
_TESTS_DIR = _ROOT / "tests"
_EVAL_SCRIPT = _ROOT / "benchmarks" / "run_eval.py"
_BANNED_MOCK_IMPORTS = frozenset({"unittest.mock", "mock"})
_BANNED_ENTRYPOINT_PREFIXES = ("vibeguard.cli.", "vibeguard.pipeline.")


def _load_eval_module():
    name = "vibeguard_run_eval"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, _EVAL_SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _iter_python_targets() -> list[Path]:
    return sorted(_TESTS_DIR.glob("test_*.py")) + [_EVAL_SCRIPT]


def test_no_mock_libraries_or_internal_entrypoint_stubs() -> None:
    violations: list[str] = []
    for path in _iter_python_targets():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in _BANNED_MOCK_IMPORTS or alias.name.startswith("unittest.mock"):
                        violations.append(f"{path.name}:{node.lineno}: banned import {alias.name}")
            elif isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                if mod in _BANNED_MOCK_IMPORTS or mod.startswith("unittest.mock"):
                    violations.append(f"{path.name}:{node.lineno}: banned import from {mod}")
            elif (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "setattr"
                and node.args
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)
                and node.args[0].value.startswith(_BANNED_ENTRYPOINT_PREFIXES)
            ):
                violations.append(f"{path.name}:{node.lineno}: stubs internal entrypoint {node.args[0].value}")
    assert violations == []


def test_no_fixed_sleeps_in_tests_or_benchmarks() -> None:
    violations: list[str] = []
    for path in _iter_python_targets():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if isinstance(node.func, ast.Attribute) and node.func.attr == "sleep":
                if isinstance(node.func.value, ast.Name) and node.func.value.id in {"time", "asyncio"}:
                    violations.append(f"{path.name}:{node.lineno}: fixed sleep {node.func.value.id}.sleep()")
    assert violations == []


def test_no_flake_masking_retries_or_inflated_timeouts() -> None:
    violations: list[str] = []
    for path in _iter_python_targets():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr == "flaky":
                violations.append(f"{path.name}:{node.lineno}: pytest.mark.flaky is banned")
            if isinstance(node, ast.Call):
                for kw in node.keywords:
                    if kw.arg == "reruns":
                        violations.append(f"{path.name}:{node.lineno}: reruns= masks flaky tests")
                    if (
                        kw.arg == "timeout"
                        and isinstance(kw.value, ast.Constant)
                        and isinstance(kw.value.value, (int, float))
                        and kw.value.value > 30
                    ):
                        violations.append(f"{path.name}:{node.lineno}: inflated timeout={kw.value.value}")
    assert violations == []


def test_eval_scan_case_fails_closed_on_judge_errors(tmp_path: Path) -> None:
    eval_mod = _load_eval_module()
    case = eval_mod.CaseSpec("negative/n01_err", "negative", tmp_path, (), "err")

    def _failing_scan(root: Path, **_kwargs: object) -> tuple[ScanResult, ScanContext]:
        ctx = ScanContext(root=root, files=[], units=[], auth_context="")
        res = ScanResult(
            root=root,
            findings=[],
            files_scanned=1,
            judge=JudgeStats(mode="offline", errors=["chunk timeout"]),
            duration_s=0.01,
        )
        return res, ctx

    with pytest.raises(RuntimeError, match="judge reported errors"):
        eval_mod.scan_case(_failing_scan, case, "offline", 0.75)


def test_eval_scan_case_fails_closed_on_mode_mismatch(tmp_path: Path) -> None:
    eval_mod = _load_eval_module()
    case = eval_mod.CaseSpec("negative/n02_mode", "negative", tmp_path, (), "mode")

    def _wrong_mode_scan(root: Path, **_kwargs: object) -> tuple[ScanResult, ScanContext]:
        ctx = ScanContext(root=root, files=[], units=[], auth_context="")
        res = ScanResult(
            root=root,
            findings=[],
            files_scanned=1,
            judge=JudgeStats(mode="offline"),
            duration_s=0.01,
        )
        return res, ctx

    with pytest.raises(RuntimeError, match="requested mode 'live' but observed 'offline'"):
        eval_mod.scan_case(_wrong_mode_scan, case, "live", 0.75)


def test_eval_offline_blocks_outbound_network() -> None:
    eval_mod = _load_eval_module()
    with eval_mod._block_outbound_network():
        with pytest.raises(RuntimeError, match="outbound network call forbidden"):
            socket.create_connection(("127.0.0.1", 1), timeout=1)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            with pytest.raises(RuntimeError, match="outbound network call forbidden"):
                sock.connect(("127.0.0.1", 1))
        finally:
            sock.close()
