"""Cross-platform unit coverage for safety-critical internals (verify, probes, jury, runtime, run)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from vibecleaner.fix_contract import EvidenceKind, ExecResult, SandboxUnavailable
from vibecleaner.jury.parsing import parse_model_json
from vibecleaner.models import Language
from vibecleaner.probes.execute import classify_probe, combined_output, generated_fault, pytest_argv, shrunk_example, under_root
from vibecleaner.probes.mutate import file_candidates, select_mutants
from vibecleaner.probes.spans import as_source_file, is_skipped_path, language_of, normalize_changed, overlaps
from vibecleaner.run.ports import probes_available, runtime_available, team_text
from vibecleaner.runtime.report import note, traced
from vibecleaner.verify.config_text import basic_toml, dig, load_ini, load_json, load_toml, requirement_name, requirement_names
from vibecleaner.verify.failures import parse_failures
from vibecleaner.verify.gate import Gate
from vibecleaner.verify.sandbox import HostSandbox, _container_env, _docker_argv, choose_image, combined_image_tag, make_sandbox
from vibecleaner.verify.signatures import Param, decode_params, encode_params, signature_changed, signature_index
from vibecleaner.fix_contract import Team


def test_verify_config_text_and_requirements() -> None:
    toml_text = (
        "[tool.pytest.ini_options]\n"
        'addopts = [\n  "--cov=app", # inline\n  "--cov-fail-under=80",\n]\n'
        'title = "a # literal"\n'
        "strict = true\n"
        "count = 42\n"
        "ratio = 0.75\n"
    )
    parsed = basic_toml(toml_text)
    assert dig(parsed, "tool", "pytest", "ini_options", "addopts") == ["--cov=app", "--cov-fail-under=80"]
    assert dig(parsed, "tool", "pytest", "ini_options", "title") == "a # literal"
    assert dig(parsed, "tool", "pytest", "ini_options", "strict") is True
    assert dig(parsed, "tool", "pytest", "ini_options", "count") == 42
    assert dig(parsed, "tool", "pytest", "ini_options", "ratio") == 0.75
    assert load_toml("= bad = [") == {}
    assert load_json('{\n // c\n /* b */\n "a": 1,\n}') == {"a": 1}
    assert load_json("[1]") == {}
    assert load_ini("[s]\nk = v\n").get("s", "k") == "v"
    assert requirement_name("My_Pkg[dev]>=1.0; python_version>='3.11'") == "my-pkg"
    assert requirement_names("# c\n-r base.txt\nPyYAML>=6\n") == {"pyyaml"}


def test_verify_signatures_and_compatibility() -> None:
    base = encode_params((Param("a", "pos", True),))
    with_opt = encode_params((Param("a", "pos", True), Param("b", "pos", False)))
    with_req = encode_params((Param("a", "pos", True), Param("b", "pos", True)))
    assert decode_params(base) == (Param("a", "pos", True),)
    assert decode_params("not json") == ()
    assert signature_changed(base, with_opt) is False
    assert signature_changed(base, with_req) is True
    assert signature_changed(with_opt, base) is True

    py_idx = signature_index("m.py", "def pub(a: int, b: int = 1, *args, **kw):\n    return a\ndef _priv():\n    pass\n")
    assert "m.py:pub" in py_idx and "m.py:_priv" not in py_idx

    ts_idx = signature_index("m.ts", "export function run(x: number, y?: string) { return x; }\n")
    assert "m.ts:run" in ts_idx


def test_verify_failures_parsers() -> None:
    def _res(out: str, err: str = "", *, timed_out: bool = False) -> ExecResult:
        return ExecResult(("cmd",), 1, out, err, 0.1, timed_out=timed_out)

    assert parse_failures(Gate("pytest", EvidenceKind.TEST_FAILURE, ("pytest",), "python"), _res("", timed_out=True))[0].summary == "pytest timed out"
    assert parse_failures(Gate("mypy", EvidenceKind.TYPE_ERROR, ("mypy",), "python"), _res("a.py:3: error: bad\n"))[0].line == 3
    assert parse_failures(Gate("pyright", EvidenceKind.TYPE_ERROR, ("pyright",), "python"), _res("a.py:4:2 - error: bad\n"))[0].line == 4
    assert parse_failures(Gate("ruff", EvidenceKind.LINT_ERROR, ("ruff",), "python"), _res("a.py:5:1: F401 unused\n"))[0].line == 5
    assert parse_failures(Gate("tsc", EvidenceKind.TYPE_ERROR, ("tsc",), "typescript"), _res("a.ts(6,1): error TS2322: bad\n"))[0].line == 6
    assert parse_failures(Gate("eslint", EvidenceKind.LINT_ERROR, ("eslint",), "javascript"), _res("a.ts\n  7:2  error  no any  no-any\n"))[0].line == 7
    assert parse_failures(Gate("vitest", EvidenceKind.TEST_FAILURE, ("vitest",), "typescript"), _res("FAIL a.test.ts\n  ● adds\n    ❯ a.test.ts:8:1\n"))[0].line == 8


def test_verify_sandbox_cross_platform(tmp_path: Path) -> None:
    sb = make_sandbox(tmp_path, kind="host")
    assert isinstance(sb, HostSandbox)
    with pytest.raises(SandboxUnavailable):
        make_sandbox(tmp_path, kind="invalid")  # type: ignore[arg-type]

    assert choose_image(tmp_path) == "python:3.12-slim"
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    assert choose_image(tmp_path) == "node:22-slim"
    (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\n", encoding="utf-8")
    assert choose_image(tmp_path) == combined_image_tag()

    res = sb.run((sys.executable, "-c", "print('ok')"), cwd=tmp_path, timeout_s=10)
    assert res.ok and res.stdout.strip() == "ok"
    with pytest.raises(ValueError, match="outside the sandbox root"):
        sb.run((sys.executable, "-c", "pass"), cwd=tmp_path.parent, timeout_s=5)

    argv = _docker_argv(
        container="vg-1",
        image="python:3.12-slim",
        root=tmp_path,
        cwd=tmp_path,
        command=("pytest",),
        network=False,
        env=_container_env({"K": "V"}),
    )
    assert "--network" in argv and "K=V" in argv


def test_probes_spans_mutate_and_execute(tmp_path: Path) -> None:
    assert normalize_changed(tmp_path, {"./a.py": frozenset({1, 0}), "../escape.py": frozenset({1})}) == {"a.py": frozenset({1})}
    assert is_skipped_path("tests/test_a.py") is True and is_skipped_path("src/a.py") is False
    assert overlaps(2, 5, frozenset({4})) is True
    assert language_of("a.py") is Language.PYTHON and as_source_file("a.md", "hi") is None

    py_src = "def f(a: int, b: bool) -> int:\n    if not b:\n        return 0\n    if a < 5 and b:\n        return 1\n    return 2\n"
    muts = file_candidates("f.py", py_src, frozenset(range(1, 7)))
    assert {"cmp_flip", "bool_flip", "negate_if", "drop_guard", "return_none", "off_by_one"} <= {m.operator for m in muts}
    assert len(select_mutants(muts, 3)) == 3

    ts_src = "export async function g(x: number) {\n  if (x < 2) { return await Promise.resolve(1); }\n  return 0;\n}\n"
    ts_muts = file_candidates("g.ts", ts_src, frozenset({1, 2, 3}))
    assert {"cmp_flip", "remove_await", "off_by_one"} <= {m.operator for m in ts_muts}

    assert pytest_argv("python", "t.py", stop=True) == ("python", "-m", "pytest", "-q", "-x", "t.py")
    assert classify_probe(ExecResult(("p",), 0, "ok", "", 0.1), "test_x.py") == "pass"
    assert classify_probe(ExecResult(("p",), 124, "", "", 1.0, timed_out=True), "test_x.py") == "counterexample"
    assert "Falsifying example:" in shrunk_example("Falsifying example: f(x=0)\n====")
    assert generated_fault("SyntaxError in test_x.py:1", "test_x.py") is True
    assert "timed out" in combined_output(ExecResult(("p",), 124, "", "", 2.0, timed_out=True))
    with pytest.raises(ValueError, match="escapes"):
        under_root(tmp_path, tmp_path.parent / "x.py")


def test_jury_parsing_runtime_report_and_ports() -> None:
    assert parse_model_json('```json\n{"ok": true}\n```') == {"ok": True}
    assert parse_model_json("prose [1, 2] end") == [1, 2]
    assert parse_model_json("no json here") is None
    assert parse_model_json("{unfinished") is None

    assert note("hi").summary == "hi"
    ev = traced(EvidenceKind.RUNTIME_TRACE, "boom", ("python", "app.py"), ("curl", "/"), "500", "repro", file="app.py")
    assert ev.command == ("python", "app.py", "--", "curl", "/")

    assert probes_available() is True
    assert runtime_available() is True
    assert isinstance(team_text(Team(host=None, providers=())), str)
