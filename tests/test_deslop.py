"""Deslop detectors: one positive and one sharp negative per rule, plus repo smoke."""

from __future__ import annotations

from pathlib import Path, PurePosixPath

from vibecleaner.collector import walk_repo
from vibecleaner.deslop import (
    CONCERN_BRIEFS,
    DESLOP_CONCERNS,
    build_cross_refs,
    detect_deslop,
    detect_repo_deslop,
    slop_score,
)
from vibecleaner.deterministic import run_deterministic
from vibecleaner.models import Category, Finding, Language, ScanContext, Severity, SourceFile

_CONCERNS = frozenset(
    {"dedupe", "types", "dead-code", "cycles", "weak-types", "defensive-code", "legacy", "ai-slop"}
)
_MAPPED = (
    "D9.weak_type",
    "D9.debug_leftover",
    "D9.larp_comment",
    "D9.legacy_fallback",
    "D9.pointless_catch",
    "D9.unused_private",
    "D9.duplicate_function",
    "D9.circular_import",
    "D9.mocked_production",
    "D9.missing_dependency",
    "D9.slopsquat",
    "D9.contract_drift",
    "D9.migration_hazard",
    "D9.env_parity",
    "D9.assertion_gap",
    "D9.flaky_test",
    "D9.prompt_leak",
    "D9.missing_telemetry",
    "D9.loop_io",
    "D9.boundary_schema",
    "D9.graphql_drift",
    "D9.registry_missing",
    "D6a.silent_exception",
    "D6a.deprecated_sdk",
    "D6a.passthrough_wrapper",
    "D6a.god_file",
    "D6a.implicit_coupling",
    "D6a.layer_folder",
    "D6a.illegal_state",
    "D6a.shotgun_surgery",
    "D6a.layering_violation",
    "D6b.hardcoded_mock_stub",
    "D6c.llm_prose",
    "D9.expired_ttl",
)


def _sf(path: str, text: str, language: Language | None = None) -> SourceFile:
    if language is None:
        language = {
            ".py": Language.PYTHON,
            ".ts": Language.TYPESCRIPT,
            ".tsx": Language.TSX,
            ".js": Language.JAVASCRIPT,
        }.get(PurePosixPath(path).suffix, Language.OTHER)
    return SourceFile(path=path, abs_path=Path(path), language=language, text=text)


def _of(findings: list[Finding], rule_id: str) -> list[Finding]:
    return [finding for finding in findings if finding.rule_id == rule_id]


def _line(text: str, needle: str, occurrence: int = 1) -> int:
    seen = 0
    for index, line in enumerate(text.splitlines(), start=1):
        if needle in line:
            seen += 1
            if seen == occurrence:
                return index
    raise AssertionError(f"{needle!r} occurrence {occurrence} not in text")


def test_concerns_cover_lanes_and_score_weights() -> None:
    assert set(DESLOP_CONCERNS) == set(_MAPPED)
    assert set(DESLOP_CONCERNS.values()) <= _CONCERNS
    assert set(CONCERN_BRIEFS) == _CONCERNS
    assert DESLOP_CONCERNS["D9.weak_type"] == "weak-types"
    assert DESLOP_CONCERNS["D9.pointless_catch"] == "defensive-code"
    assert DESLOP_CONCERNS["D6a.silent_exception"] == "defensive-code"
    assert DESLOP_CONCERNS["D9.legacy_fallback"] == "legacy"
    assert DESLOP_CONCERNS["D6a.deprecated_sdk"] == "legacy"
    assert DESLOP_CONCERNS["D9.larp_comment"] == "ai-slop"
    assert DESLOP_CONCERNS["D6c.llm_prose"] == "ai-slop"
    assert DESLOP_CONCERNS["D9.debug_leftover"] == "ai-slop"
    assert DESLOP_CONCERNS["D6b.hardcoded_mock_stub"] == "ai-slop"
    assert DESLOP_CONCERNS["D9.unused_private"] == "dead-code"
    assert DESLOP_CONCERNS["D9.duplicate_function"] == "dedupe"
    assert DESLOP_CONCERNS["D6a.passthrough_wrapper"] == "dedupe"
    assert DESLOP_CONCERNS["D6a.god_file"] == "dedupe"
    assert DESLOP_CONCERNS["D9.circular_import"] == "cycles"
    assert DESLOP_CONCERNS["D9.mocked_production"] == "ai-slop"
    assert DESLOP_CONCERNS["D9.missing_dependency"] == "legacy"
    assert all(brief.endswith(".") and len(brief.split()) > 8 for brief in CONCERN_BRIEFS.values())

    medium = Finding("D9.weak_type", "a.ts", 1, "any")
    low = Finding("D9.larp_comment", "a.ts", 2, "for now")
    high = Finding("D6a.deprecated_sdk", "a.py", 3, "old sdk")
    security = Finding("D1.hardcoded_secret", "a.py", 4, "secret")
    assert slop_score([], 0) == 100
    assert slop_score([], 4) == 100
    assert slop_score([medium], 1) == 70
    assert slop_score([low], 1) == 90
    assert slop_score([high], 1) == 40
    assert slop_score([security], 1) == 100
    assert slop_score([medium, low], 1) == 60
    assert security.category == Category.SECURITY
    assert medium.severity == Severity.MEDIUM


def test_weak_type_flags_silencers_and_skips_explained_or_real_types() -> None:
    ts = """
const loose: any = 1;
const items: any[] = [];
const rows: Array<any> = [];
const bag: Record<string, any> = {};
const casted = loose as any;
const doubled = loose as unknown as string;
const asserted = <any>loose;
// @ts-ignore
const ignored = 1;
// @ts-nocheck
// @ts-expect-error the checker is wrong about this call
const kept = call(loose);
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function take(value: unknown): string {
  if (typeof value === "string") {
    return value;
  }
  return "";
}
const narrowed = loose as unknown;
"""
    findings = _of(detect_deslop(_sf("src/types.ts", ts)), "D9.weak_type")
    lines = {finding.line for finding in findings}
    assert _line(ts, "const loose: any") in lines
    assert _line(ts, "any[]") in lines
    assert _line(ts, "Array<any>") in lines
    assert _line(ts, "Record<string, any>") in lines
    assert _line(ts, "as any") in lines
    assert _line(ts, "as unknown as string") in lines
    assert _line(ts, "<any>loose") in lines
    assert _line(ts, "@ts-ignore") in lines
    assert _line(ts, "@ts-nocheck") in lines
    assert _line(ts, "eslint-disable") in lines
    assert _line(ts, "@ts-expect-error") not in lines
    assert _line(ts, "value: unknown") not in lines
    assert _line(ts, "as unknown;") not in lines

    py = """
from typing import Any, cast
import typing

def fetch(payload: Any) -> Any:
    return payload

hidden = cast(Any, fetch(1))
also = typing.cast(Any, fetch(1))
kept = cast(str, fetch(1))
labeled = fetch(1)  # type: ignore
coded = fetch(1)  # type: ignore[arg-type]
note = "cast(Any, x)  # type: ignore"
"""
    py_findings = _of(detect_deslop(_sf("app/types.py", py)), "D9.weak_type")
    py_lines = {finding.line for finding in py_findings}
    assert _line(py, "payload: Any") in py_lines
    assert any(finding.message == "Annotation is bare Any" for finding in py_findings)
    assert _line(py, "cast(Any, fetch") in py_lines
    assert _line(py, "typing.cast(Any, fetch") in py_lines
    assert _line(py, "cast(str, fetch") not in py_lines
    assert _line(py, "# type: ignore") in py_lines
    assert _line(py, "type: ignore[arg-type]") not in py_lines
    assert _line(py, 'note = "cast') not in py_lines

    generated = "export const value: any = 1;\n"
    assert detect_deslop(_sf("types.d.ts", generated)) == []
    assert detect_deslop(_sf("supabase/migrations/001_init.py", "x = cast(Any, 1)\n")) == []
    assert detect_deslop(_sf("tests/test_types.py", "x = 1  # type: ignore\n")) == []


def test_bare_any_annotation_flags_whole_type_only() -> None:
    text = """
from typing import Any, Callable, cast
import typing

def widen(value: Any) -> Any:
    return cast(Any, value)

def kept(value: dict[str, Any]) -> list[Any]:
    cb: Callable[..., Any] = value
    bag: dict[str, Any] = {}
    return []

def aliased(value: typing.Any) -> typing.Any:
    quoted: "Any" = value
    return value

name: Any
optional: Any | None = None

def kept_object(value: object) -> object:
    return value  # type: ignore[no-any-return]
"""
    findings = _of(detect_deslop(_sf("src/types.py", text)), "D9.weak_type")
    lines = {finding.line for finding in findings}
    assert _line(text, "def widen") in lines
    assert any(finding.message == "Annotation is bare Any" and finding.line == _line(text, "def widen") for finding in findings)
    assert _line(text, "cast(Any, value)") in lines
    assert _line(text, "def kept") not in lines
    assert _line(text, "cb: Callable") not in lines
    assert _line(text, "bag: dict") not in lines
    assert _line(text, "def aliased") in lines
    assert _line(text, 'quoted: "Any"') in lines
    assert _line(text, "name: Any") in lines
    assert _line(text, "optional: Any") not in lines
    assert _line(text, "def kept_object") not in lines
    assert _line(text, "type: ignore[no-any-return]") not in lines

    split = "def widen(\n    value: Any,\n) -> Any:\n    return value\n"
    split_lines = {finding.line for finding in _of(detect_deslop(_sf("src/split.py", split)), "D9.weak_type")}
    assert _line(split, "value: Any") in split_lines
    assert _line(split, ") -> Any") in split_lines
    assert _line(split, "def widen") not in split_lines


def test_debug_leftover_is_app_code_only_for_console() -> None:
    app = """
export function load() {
  debugger;
  console.log("load");
  console.debug("load");
  console.error("load");
  console.warn("load");
  console.info("load");
}
"""
    findings = _of(detect_deslop(_sf("app/api/load.ts", app)), "D9.debug_leftover")
    messages = {finding.message for finding in findings}
    assert "Debug leftover: debugger" in messages
    assert "Debug leftover: console.log" in messages
    assert "Debug leftover: console.debug" in messages
    assert all("error" not in message and "warn" not in message and "info" not in message for message in messages)

    script = "console.log('build');\ndebugger;\n"
    script_findings = _of(detect_deslop(_sf("scripts/build.ts", script)), "D9.debug_leftover")
    assert [finding.message for finding in script_findings] == ["Debug leftover: debugger"]
    assert detect_deslop(_sf("src/cli.ts", "console.log('boot');\n")) == []
    assert detect_deslop(_sf("app/next.config.ts", "console.log('cfg');\n")) == []
    assert _of(detect_deslop(_sf("bin/run.js", "console.log('x');\n")), "D9.debug_leftover") == []

    py = """
import pdb
import ipdb
from pdb import set_trace

def run():
    breakpoint()
    pdb.set_trace()
    print("ready")
"""
    py_findings = _of(detect_deslop(_sf("server/run.py", py)), "D9.debug_leftover")
    py_messages = [finding.message for finding in py_findings]
    assert "Debug leftover: import pdb" in py_messages
    assert "Debug leftover: import ipdb" in py_messages
    assert "Debug leftover: breakpoint" in py_messages
    assert "Debug leftover: pdb.set_trace" in py_messages
    assert all("print" not in message for message in py_messages)
    assert _line(py, "print(") not in {finding.line for finding in py_findings}


def test_console_log_flags_every_shipped_script() -> None:
    service = """
export function ship(value: string): void {
  console.log(value);
  console.debug(value);
  console.error(value);
}
"""
    findings = _of(detect_deslop(_sf("services/log.ts", service)), "D9.debug_leftover")
    messages = {finding.message for finding in findings}
    assert messages == {"Debug leftover: console.log", "Debug leftover: console.debug"}
    assert _of(detect_deslop(_sf("packages/web/log.ts", 'console.log("x");\n')), "D9.debug_leftover") != []
    assert _of(detect_deslop(_sf("scripts/build.ts", "console.log('build');\n")), "D9.debug_leftover") == []
    assert _of(detect_deslop(_sf("bin/run.js", "console.log('x');\n")), "D9.debug_leftover") == []
    assert _of(detect_deslop(_sf("cli/main.ts", "console.log('x');\n")), "D9.debug_leftover") == []
    assert detect_deslop(_sf("src/cli.ts", "console.log('boot');\n")) == []
    assert detect_deslop(_sf("config.ts", "console.log('cfg');\n")) == []
    assert detect_deslop(_sf("app/next.config.ts", "console.log('cfg');\n")) == []
    assert detect_deslop(_sf("services/log.test.ts", "console.log('t');\n")) == []


def test_larp_comment_matches_narration_not_real_notes() -> None:
    text = """
# for now skip the cache
# temporary workaround until the index exists
# hack: drop empty rows
# previously this wrote the audit row
# TODO: implement
# FIXME: implement the writer
# TODO: add retry with backoff
# noqa: E501 — for now
# SPDX-License-Identifier: MIT
def load(row):
    \"\"\"Return the row for now, previously stored as JSON.\"\"\"
    return row  # the row for the caller
note = "for now"
# return load(row)
"""
    findings = _of(detect_deslop(_sf("app/load.py", text)), "D9.larp_comment")
    lines = {finding.line for finding in findings}
    assert _line(text, "for now skip") not in lines
    assert _line(text, "temporary workaround") in lines
    assert _line(text, "# hack:") in lines
    assert _line(text, "previously this") not in lines
    assert _line(text, "TODO: implement") in lines
    assert _line(text, "FIXME: implement") in lines
    assert _line(text, "TODO: add retry") not in lines
    assert _line(text, "noqa") not in lines
    assert _line(text, "SPDX") not in lines
    assert _line(text, "Return the row") not in lines
    assert _line(text, "the row for the caller") not in lines
    assert _line(text, 'note = "for now"') not in lines
    assert _line(text, "# return load") not in lines
    assert len(findings) == 4

    block = "/* for now\n * keep the old implementation\n */\nexport const n = 1;\n"
    block_findings = _of(detect_deslop(_sf("src/n.ts", block)), "D9.larp_comment")
    assert len(block_findings) == 1
    assert block_findings[0].line == 1


def test_larp_comment_skips_design_notes() -> None:
    text = """
def build():
    # The cache is process-local for now; Redis is a later design.
    # Callers must pass an aware datetime.
    # previously computed hashes are reused
    # The field was added in the public API and must stay.
    # temporary fix until the index exists
    # placeholder implementation
    # in a real app this would persist
    # changed to the new writer
    # replaced with the public helper
    # this path was removed
    return 1
"""
    findings = _of(detect_deslop(_sf("src/notes.py", text)), "D9.larp_comment")
    lines = {finding.line for finding in findings}
    assert _line(text, "for now") not in lines
    assert _line(text, "aware datetime") not in lines
    assert _line(text, "previously computed") not in lines
    assert _line(text, "was added") not in lines
    assert _line(text, "temporary fix") in lines
    assert _line(text, "placeholder implementation") in lines
    assert _line(text, "in a real app") in lines
    assert _line(text, "changed to") in lines
    assert _line(text, "replaced with") in lines
    assert _line(text, "was removed") in lines


def test_larp_comment_catches_antislop_code_banners_steps_and_empty_labels() -> None:
    text = """
# ========================
# -------- ROUTES --------
def handle(x):
    # Step 1: Validate input
    # Main logic
    # ✅ Validation
    # Stripe retries webhooks for 72h; dedupe by event.id.
    if x:
        return x
    # end if
    return 0
"""
    findings = _of(detect_deslop(_sf("src/handler.py", text)), "D9.larp_comment")
    lines = {finding.line for finding in findings}
    assert _line(text, "========") in lines
    assert _line(text, "ROUTES") in lines
    assert _line(text, "Step 1:") in lines
    assert _line(text, "Main logic") in lines
    assert _line(text, "Validation") in lines
    assert _line(text, "end if") in lines
    assert _line(text, "Stripe retries") not in lines


def test_legacy_fallback_needs_a_current_sibling_or_a_backup_name() -> None:
    same = """
def foo_old(value):
    return value

def foo(value):
    return value + 1

def foo_v1(value):
    return value

def foo_v2(value):
    return value + 2

def only_old(value):
    return value

class Box:
    def save_old(self):
        return 1

    def save(self):
        return 2

def save(value):
    return value
"""
    findings = _of(detect_deslop(_sf("app/flow.py", same)), "D9.legacy_fallback")
    symbols = {finding.symbol for finding in findings}
    assert symbols == {"foo_old", "foo_v1", "save_old"}
    assert all("only_old" not in (finding.symbol or "") for finding in findings)
    foo_old = next(finding for finding in findings if finding.symbol == "foo_old")
    assert "foo" in foo_old.message
    assert foo_old.line == _line(same, "def foo_old")

    old_file = _sf("app/old_flow.py", "def foo_old(value):\n    return value\n")
    current = _sf("app/flow.py", "def foo(value):\n    return value\n")
    other_dir = _sf("lib/flow.py", "def foo(value):\n    return value\n")
    cross = _of(detect_repo_deslop([old_file, current]), "D9.legacy_fallback")
    assert len(cross) == 1
    assert cross[0].file == "app/old_flow.py"
    assert cross[0].symbol == "foo_old"
    assert detect_deslop(old_file) == []
    assert _of(detect_repo_deslop([old_file, other_dir]), "D9.legacy_fallback") == []

    backup = detect_deslop(_sf("notes.bak", ""))
    assert len(backup) == 1 and backup[0].rule_id == "D9.legacy_fallback"
    copy_name = detect_deslop(_sf("copy of notes.py", "x = 1\n"))
    assert any(finding.rule_id == "D9.legacy_fallback" and finding.line == 1 for finding in copy_name)
    assert any(finding.line == 1 for finding in detect_deslop(_sf("report copy.ts", "export const n = 1;\n")))
    assert any(finding.line == 1 for finding in detect_deslop(_sf("reader_old.py", "def read():\n    return 1\n")))
    assert any(finding.line == 1 for finding in detect_deslop(_sf("reader-old.tsx", "export const n = 1;\n")))


def test_pointless_catch_is_only_a_bare_reraise() -> None:
    py = """
def bare():
    try:
        risky()
    except ValueError as err:
        raise err

def plain():
    try:
        risky()
    except ValueError:
        raise

def logged():
    try:
        risky()
    except ValueError as err:
        log(err)
        raise

def translated():
    try:
        risky()
    except KeyError:
        raise ValueError("missing") from None

def cleaned():
    try:
        risky()
    except ValueError:
        raise
    finally:
        cleanup()
"""
    findings = _of(detect_deslop(_sf("app/errs.py", py)), "D9.pointless_catch")
    lines = {finding.line for finding in findings}
    assert lines == {_line(py, "try:", 1), _line(py, "try:", 2)}

    ts = """
export function bare() {
  try {
    work();
  } catch (err) {
    throw err;
  }
}

export function logged() {
  try {
    work();
  } catch (err) {
    console.error(err);
    throw err;
  }
}
"""
    ts_findings = _of(detect_deslop(_sf("app/errs.ts", ts)), "D9.pointless_catch")
    assert len(ts_findings) == 1
    assert ts_findings[0].line == _line(ts, "try {")
    assert _line(ts, "try {", 2) != ts_findings[0].line


def test_unused_private_requires_a_single_uncalled_name() -> None:
    text = """
def _helper():
    return 1

def _used():
    return _used()

def call_helper():
    return _helper()

@deco
def _hidden():
    return 1

def __dunder():
    return 1

class _Box:
    pass

class _Kept:
    pass

__all__ = ["_Kept"]

class Shown:
    def _method(self):
        return 1
"""
    findings = _of(detect_deslop(_sf("app/priv.py", text)), "D9.unused_private")
    symbols = {finding.symbol for finding in findings}
    assert "_Box" in symbols
    assert "_helper" not in symbols
    assert "_used" not in symbols
    assert "_hidden" not in symbols
    assert "__dunder" not in symbols
    assert "_Kept" not in symbols
    assert "_method" not in symbols

    alone = "def _helper():\n    return 1\n"
    alone_findings = _of(detect_deslop(_sf("app/alone.py", alone)), "D9.unused_private")
    assert [finding.symbol for finding in alone_findings] == ["_helper"]
    assert detect_deslop(_sf("app/alone.py", alone), all_text="from app.alone import _helper\n") == []
    formatted = "def _helper():\n    return 1\n\ndef show():\n    return f'{_helper()}'\n"
    assert _of(detect_deslop(_sf("app/fmt.py", formatted)), "D9.unused_private") == []
    assert detect_deslop(_sf("pkg/__init__.py", "def _helper():\n    return 1\n")) == []

    ts = """
function helper() {
  return 1;
}

export function useHelper() {
  return helper();
}

const unused = () => 1;

export function shown() {
  return 1;
}

const exported = () => 2;
export { exported };
"""
    ts_findings = _of(detect_deslop(_sf("src/priv.ts", ts)), "D9.unused_private")
    assert {finding.symbol for finding in ts_findings} == {"unused"}


def test_unused_private_sees_other_files_and_string_constants() -> None:
    alone = "def _helper():\n    return 1\n"
    user = "from pkg.a import _helper\n\ndef run():\n    return _helper()\n"
    defined = _sf("pkg/a.py", alone)
    caller = _sf("pkg/b.py", user)
    assert [finding.symbol for finding in _of(detect_deslop(defined), "D9.unused_private")] == ["_helper"]
    assert _of(detect_deslop(defined, all_text=caller.text), "D9.unused_private") == []
    assert _of(detect_deslop(defined, cross_refs=build_cross_refs([defined, caller])), "D9.unused_private") == []
    other = _sf("pkg/c.py", "def run():\n    return _helper_v2()\n")
    still = _of(detect_deslop(defined, cross_refs=build_cross_refs([defined, other])), "D9.unused_private")
    assert [finding.symbol for finding in still] == ["_helper"]

    getattr_mod = """
import sys
def _helper():
    return 1
def run():
    return getattr(sys.modules[__name__], "_helper")()
"""
    assert _of(detect_deslop(_sf("src/reg.py", getattr_mod)), "D9.unused_private") == []
    registry = 'def _helper():\n    return 1\nHANDLERS = {"_helper": None}\n'
    assert _of(detect_deslop(_sf("src/registry.py", registry)), "D9.unused_private") == []
    decoy = 'def _helper():\n    return 1\nHANDLERS = {"_other": None}\n'
    assert [finding.symbol for finding in _of(detect_deslop(_sf("src/decoy.py", decoy)), "D9.unused_private")] == ["_helper"]
    script = 'function helper() {\n  return 1;\n}\nconst key = "helper";\n'
    assert _of(detect_deslop(_sf("src/reg.ts", script)), "D9.unused_private") == []
    dead = "function helper() {\n  return 1;\n}\n"
    assert [finding.symbol for finding in _of(detect_deslop(_sf("src/dead.ts", dead)), "D9.unused_private")] == ["helper"]

    used = ScanContext(root=Path("."), files=[defined, caller, _sf("pkg/__init__.py", "")], units=[], auth_context="")
    assert _of(run_deterministic(used), "D9.unused_private") == []
    lone = ScanContext(root=Path("."), files=[defined, _sf("pkg/__init__.py", "")], units=[], auth_context="")
    lone_hits = _of(run_deterministic(lone), "D9.unused_private")
    assert [finding.symbol for finding in lone_hits] == ["_helper"]


def test_duplicate_function_matches_renamed_locals_across_files() -> None:
    first = """
def build_invoice(account, entries):
    total = 0
    count = 0
    index = 0
    limit = 1
    extra = 2
    total += account.base
    count += entries.size
    return finalize(account, total, count, index, limit, extra)
"""
    second = """
def build_bill(customer, lines):
    amount = 0
    tally = 0
    cursor = 0
    cap = 1
    bonus = 2
    amount += customer.base
    tally += lines.size
    return finalize(customer, amount, tally, cursor, cap, bonus)
"""
    short_a = "\n".join(
        [
            "def short_a(user, rows):",
            "    total = 0",
            "    count = 0",
            "    index = 0",
            "    limit = 1",
            "    total += user.base",
            "    count += rows.size",
            "    return finalize(user, total, count, index, limit)",
            "",
        ]
    )
    short_b = short_a.replace("short_a", "short_b").replace("user", "account").replace("rows", "lines")
    trivial = "def only_returns(value):\n" + "\n".join(f"    return value + {index}" for index in range(8)) + "\n"
    table_a = _tariff("ground", 420)
    table_b = _tariff("express", 890)
    files = [
        _sf("app/a.py", first),
        _sf("lib/b.py", second),
        _sf("app/short_a.py", short_a),
        _sf("app/short_b.py", short_b),
        _sf("app/triv_a.py", trivial),
        _sf("app/triv_b.py", trivial.replace("only_returns", "also_returns")),
        _sf("shipping/a.py", table_a),
        _sf("shipping/b.py", table_b),
    ]
    findings = _of(detect_repo_deslop(files), "D9.duplicate_function")
    assert len(findings) == 1
    assert findings[0].file == "lib/b.py"
    assert findings[0].message == "Duplicate of app/a.py:2"
    assert findings[0].symbol == "build_bill"
    assert _of(detect_repo_deslop([_sf("tests/test_a.py", first), _sf("tests/test_b.py", second)]), "D9.duplicate_function") == []


def _tariff(service: str, base: int) -> str:
    lines = [f"def {service}_base(zone, weight):"]
    for step in range(8):
        lines.append(f"    if weight <= {(step + 1) * 8}:")
        lines.append(f"        return {base + step}")
    lines.append(f"    raise ValueError('{service} too heavy')")
    return "\n".join(lines) + "\n"


def test_circular_import_ignores_type_checking_and_lazy_imports() -> None:
    a = "from .b import value\nVALUE = 1\n"
    b = "from .a import VALUE\nvalue = 2\n"
    findings = _of(
        detect_repo_deslop([_sf("pkg/a.py", a), _sf("pkg/b.py", b)]),
        "D9.circular_import",
    )
    assert len(findings) == 1
    assert findings[0].file == "pkg/a.py"
    assert findings[0].line == 1
    assert findings[0].message == "pkg/a.py -> pkg/b.py -> pkg/a.py"

    lazy_a = "def load():\n    from .b import value\n    return value\n"
    lazy_b = "from .a import load\n"
    assert (
        _of(
            detect_repo_deslop([_sf("pkg/a.py", lazy_a), _sf("pkg/b.py", lazy_b)]),
            "D9.circular_import",
        )
        == []
    )

    typed_a = "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    from .b import value\nVALUE = 1\n"
    typed_b = "from .a import VALUE\n"
    assert (
        _of(
            detect_repo_deslop([_sf("pkg/a.py", typed_a), _sf("pkg/b.py", typed_b)]),
            "D9.circular_import",
        )
        == []
    )
    assert (
        _of(
            detect_repo_deslop(
                [
                    _sf("pkg/a.py", "import os\nfrom fastapi import FastAPI\n"),
                    _sf("pkg/b.py", "import os\n"),
                ]
            ),
            "D9.circular_import",
        )
        == []
    )

    ts_a = 'import { b } from "./b";\nexport const a = 1;\n'
    ts_b = 'import { a } from "./a";\nexport const b = 2;\n'
    ts_findings = _of(
        detect_repo_deslop([_sf("app/a.ts", ts_a), _sf("app/b.ts", ts_b)]),
        "D9.circular_import",
    )
    assert len(ts_findings) == 1
    assert ts_findings[0].message == "app/a.ts -> app/b.ts -> app/a.ts"

    type_a = 'import type { B } from "./b";\nexport const a = 1;\n'
    type_b = 'import { a } from "./a";\nexport interface B { n: number }\n'
    assert (
        _of(
            detect_repo_deslop([_sf("app/a.ts", type_a), _sf("app/b.ts", type_b)]),
            "D9.circular_import",
        )
        == []
    )

    alias_a = 'import { b } from "@/b";\nexport const a = 1;\n'
    alias_b = 'import { a } from "./a";\nexport const b = 2;\n'
    alias = _of(
        detect_repo_deslop([_sf("src/a.ts", alias_a), _sf("src/b.ts", alias_b)]),
        "D9.circular_import",
    )
    assert len(alias) == 1
    assert alias[0].message == "src/a.ts -> src/b.ts -> src/a.ts"


def test_repo_scan_does_not_crash_and_negative_benchmarks_stay_clean() -> None:
    root = Path(__file__).resolve().parents[1]
    files = walk_repo(root)
    per_file: list[Finding] = []
    repo_refs = build_cross_refs(files)
    for source in files:
        per_file.extend(detect_deslop(source, cross_refs=repo_refs))
    cross = detect_repo_deslop(files)
    print(
        "repo",
        f"files={len(files)}",
        f"per_file={len(per_file)}",
        f"cross={len(cross)}",
        f"score={slop_score(per_file + cross, len(files))}",
    )
    _print_counts("repo-per-file", per_file)
    _print_counts("repo-cross", cross)

    negative = root / "benchmarks" / "negative"
    assert negative.is_dir()
    for case in sorted(path for path in negative.iterdir() if path.is_dir()):
        case_files = walk_repo(case)
        case_refs = build_cross_refs(case_files)
        hits: list[Finding] = []
        for source in case_files:
            hits.extend(detect_deslop(source, cross_refs=case_refs))
        hits.extend(detect_repo_deslop(case_files))
        if hits:
            rendered = ", ".join(f"{hit.rule_id} {hit.file}:{hit.line} {hit.message}" for hit in hits)
            print(f"negative {case.name}: {rendered}")
        assert hits == [], case.name


def _print_counts(label: str, findings: list[Finding]) -> None:
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.rule_id] = counts.get(finding.rule_id, 0) + 1
    summary = ", ".join(f"{rule}={counts[rule]}" for rule in sorted(counts)) or "none"
    print(f"{label}: {summary}")
