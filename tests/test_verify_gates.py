"""Gate detection follows the repo's own toolchain, then a config override."""

import json
from pathlib import Path

from vibeguard.fix_contract import EvidenceKind, ExecResult, FixContext, Team, Verdict
from vibeguard.verify import detect_gates, run_gates
from vibeguard.verify.gate import Gate


def _commands(root: Path) -> list[tuple[str, ...]]:
    return [gate.command for gate in detect_gates(root)]


def test_go_mod_uses_go_test(tmp_path: Path) -> None:
    (tmp_path / "go.mod").write_text("module example.com/pay\n\ngo 1.22\n", encoding="utf-8")
    assert ("go", "test", "./...") in _commands(tmp_path)
    gate = next(item for item in detect_gates(tmp_path) if item.name == "go")
    assert ("go", "test", ".") in gate.attempts()


def test_makefile_test_target_is_detected(tmp_path: Path) -> None:
    (tmp_path / "Makefile").write_text("test:\n\t./tests/visible.sh\ncheck:\n\t./tests/visible.sh\n", encoding="utf-8")
    (tmp_path / "page.sh").write_text("#!/bin/sh\n", encoding="utf-8")
    assert ("make", "test") in _commands(tmp_path)
    gate = next(item for item in detect_gates(tmp_path) if item.name == "make")
    assert ("make", "check") in gate.attempts()


def test_config_test_command_overrides_detection(tmp_path: Path) -> None:
    (tmp_path / "go.mod").write_text("module example.com/pay\n\ngo 1.22\n", encoding="utf-8")
    config = tmp_path / ".vibeguard"
    config.mkdir()
    (config / "config.json").write_text(
        json.dumps({"test": "make check"}),
        encoding="utf-8",
    )
    commands = _commands(tmp_path)
    assert ("make", "check") in commands
    assert ("go", "test", "./...") not in commands


class _ScriptSandbox:
    name = "host"

    def __init__(self, root: Path, codes: dict[tuple[str, ...], int]) -> None:
        self.root = root
        self.codes = codes
        self.calls: list[tuple[str, ...]] = []

    def run(self, command, *, cwd, timeout_s, network=False, env=None):
        del cwd, timeout_s, network, env
        argv = tuple(command)
        self.calls.append(argv)
        code = self.codes.get(argv, 127)
        err = "not found" if code == 127 else "failed"
        return ExecResult(argv, code, "", err, 0.0)


def test_missing_binary_tries_the_next_spelling(tmp_path: Path) -> None:
    sandbox = _ScriptSandbox(tmp_path, {("pytest", "-q"): 0})
    gate = Gate("pytest", EvidenceKind.TEST_FAILURE, ("python", "-m", "pytest"), "python", (("pytest", "-q"),))
    ctx = FixContext(root=tmp_path, sandbox=sandbox, team=Team(host=None))
    result = run_gates(ctx, tmp_path, [gate])
    assert result.verdict is Verdict.PASS
    assert sandbox.calls == [("python", "-m", "pytest"), ("pytest", "-q")]


def test_a_real_failure_does_not_try_the_next_spelling(tmp_path: Path) -> None:
    sandbox = _ScriptSandbox(tmp_path, {("python", "-m", "pytest"): 1})
    gate = Gate("pytest", EvidenceKind.TEST_FAILURE, ("python", "-m", "pytest"), "python", (("pytest", "-q"),))
    ctx = FixContext(root=tmp_path, sandbox=sandbox, team=Team(host=None))
    result = run_gates(ctx, tmp_path, [gate])
    assert result.verdict is Verdict.REVISE
    assert sandbox.calls == [("python", "-m", "pytest")]
