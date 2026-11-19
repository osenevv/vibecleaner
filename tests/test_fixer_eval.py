"""Integrity checks for the fixer calibration sets and harness."""

from __future__ import annotations

import importlib.util
import shutil
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_EVAL_SCRIPT = _ROOT / "benchmarks" / "run_fixer_eval.py"


def _load():
    name = "vibecleaner_run_fixer_eval"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, _EVAL_SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class _RaisingApi:
    def snapshot(self, tree: Path) -> None:
        raise RuntimeError("snapshot failed")


def test_every_repair_case_has_spec_hidden_tests_and_labels() -> None:
    harness = _load()
    labels = harness.load_labels()
    repair = labels["repair"]
    found = {path.name for path in harness.case_dirs("repair")}
    assert found == set(repair)
    for name, entry in repair.items():
        case = harness.BENCHMARKS / "repair" / name
        assert (case / "spec.md").is_file(), name
        assert (case / "repo").is_dir(), name
        hidden = [path for path in (case / "hidden_tests").rglob("*") if path.is_file()]
        assert hidden, name
        assert entry["expected"] in {"fixed", "needs_you"}
        command, _into = harness.hidden_command(name, entry)
        assert command
    tamper = labels["tamper"]
    assert {path.name for path in harness.case_dirs("tamper")} == set(tamper)
    for name, entry in tamper.items():
        case = harness.BENCHMARKS / "tamper" / name
        assert (case / "before").is_dir(), name
        assert (case / "after").is_dir(), name
        assert entry["expected"] in {"tamper", "clean"}
    runtime = labels["runtime"]
    assert {path.name for path in harness.case_dirs("runtime")} == set(runtime)
    for name, entry in runtime.items():
        case = harness.BENCHMARKS / "runtime" / name
        assert (case / "spec.md").is_file(), name
        assert entry["expected"] == "clean" or entry["expected"] in harness._EVIDENCE_KINDS
    make_repo = harness.BENCHMARKS / "repair" / "r11_make_only" / "repo"
    makefile = (make_repo / "Makefile").read_text(encoding="utf-8")
    assert "\ntest:" in makefile or makefile.startswith("test:")
    for blocked in ("pytest.ini", "go.mod", "pyproject.toml", "package.json", "Cargo.toml"):
        assert not (make_repo / blocked).exists()
    go_repo = harness.BENCHMARKS / "repair" / "r12_go_refund" / "repo"
    assert (go_repo / "go.mod").is_file()
    assert not (go_repo / "pytest.ini").exists()


def test_hidden_tests_fail_on_the_broken_tree(tmp_path: Path) -> None:
    harness = _load()
    labels = harness.load_labels()["repair"]
    for name, entry in labels.items():
        case = harness.BENCHMARKS / "repair" / name
        work = tmp_path / name
        harness.copy_tree(case / "repo", work)
        if name == "r11_make_only":
            visible = harness.run_command(work, ["make", "test"])
            visible_output = visible.stdout + visible.stderr
            assert visible.returncode != 0, visible_output
        if name == "r12_go_refund":
            if shutil.which("go") is None:
                continue
            visible = harness.run_command(work, ["go", "test", "-count=1", "./payments"])
            visible_output = visible.stdout + visible.stderr
            assert visible.returncode == 0, visible_output
            assert "ok" in visible_output
        command, into = harness.hidden_command(name, entry)
        harness.stage_hidden(work, case, into)
        proc = harness.run_command(work, command)
        output = proc.stdout + proc.stderr
        assert proc.returncode == 1, f"{name}\n{output}"
        assert "command not found" not in output
        assert "No module named" not in output
        assert "ModuleNotFoundError" not in output
        assert "collected 0" not in output
        if command[0] == "python":
            assert "FAILED" in output or "ERROR" in output
        elif command[0] == "go":
            assert "--- FAIL:" in output
        else:
            assert "mismatch" in output


def test_tamper_before_trees_pass(tmp_path: Path) -> None:
    harness = _load()
    for case in harness.case_dirs("tamper"):
        work = tmp_path / case.name
        harness.copy_tree(case / "before", work)
        proc = harness.run_command(work, ["python", "-m", "pytest", "-q", "-p", "no:cacheprovider"])
        output = proc.stdout + proc.stderr
        assert proc.returncode == 0, f"{case.name}\n{output}"
        assert "passed" in output


def test_harness_exits_2_when_the_api_raises(capsys: pytest.CaptureFixture[str]) -> None:
    harness = _load()
    code = harness.main(
        ["--set", "tamper", "--sandbox", "host", "--no-local"],
        api=_RaisingApi(),
    )
    captured = capsys.readouterr()
    assert code == 2
    assert "snapshot failed" in captured.err
    assert "1.000" not in captured.out
