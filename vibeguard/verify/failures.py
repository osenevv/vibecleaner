"""Turn gate output into one Evidence per failure."""

from __future__ import annotations

import re
from pathlib import PurePosixPath

from vibeguard.fix_contract import Evidence, ExecResult
from vibeguard.verify.gate import Gate

_PYTEST_FAILED = re.compile(r"^(?:FAILED|ERROR)\s+(\S+?)(?:\s+-\s+(.*?))?\s*$", re.MULTILINE)
_FILE_LINE = re.compile(r"^(.+?):(\d+):", re.MULTILINE)
_MYPY = re.compile(r"^(.+?):(\d+):(?:\d+:)?\s*(?:error|warning):\s*(.+)$", re.MULTILINE)
_PYRIGHT = re.compile(r"^(.+?):(\d+):\d+\s+-\s+(?:error|warning):\s*(.+)$", re.MULTILINE)
_RUFF = re.compile(
    r"^(.+?):(\d+):\d+:\s+([A-Z][0-9]+)\s+(?:\[\*\]\s+)?(.+)$",
    re.MULTILINE,
)
_TSC = re.compile(r"^(.+?)\((\d+),\d+\):\s+error\s+(TS\d+):\s*(.*)$", re.MULTILINE)
_ESLINT_UNIX = re.compile(r"^(.+?\.(?:[cm]?[jt]sx?)):(\d+):\d+:\s+(.+)$", re.MULTILINE)
_ESLINT_STYLISH = re.compile(r"^\s+(\d+):\d+\s+(error|warning)\s+(.+?)\s{2,}(\S+)\s*$")
_ESLINT_FILE = re.compile(r"^\s*(\S+\.(?:[cm]?[jt]sx?))\s*$")
_FAIL_BLOCK = re.compile(r"(?=^FAIL\s+)", re.MULTILINE)
_FAIL_PATH = re.compile(r"^FAIL\s+(\S+\.(?:[cm]?[jt]sx?))")
_BULLET = re.compile(r"^[\s]*●\s+(.+)$", re.MULTILINE)
_STACK_LINE = re.compile(r"(?:❯|at .+?\()(.+?):(\d+):\d+")


def parse_failures(gate: Gate, result: ExecResult) -> tuple[Evidence, ...]:
    gate = Gate(gate.name, gate.kind, result.command, gate.language, gate.alts)
    text = _combined(result)
    if result.timed_out:
        return (
            _evidence(gate, f"{gate.name} timed out", file=None, line=None, output=text),
        )
    found = _PARSERS.get(gate.name, _unknown)(gate, text)
    if not found:
        return _unknown(gate, text)
    return found


def _pytest(gate: Gate, text: str) -> tuple[Evidence, ...]:
    found: list[Evidence] = []
    for match in _PYTEST_FAILED.finditer(text):
        nodeid = match.group(1)
        message = (match.group(2) or "failed").strip()
        file = nodeid.split("::", 1)[0]
        found.append(_evidence(gate, message, file, _line_for(text, file), text))
    return tuple(found)


def _mypy(gate: Gate, text: str) -> tuple[Evidence, ...]:
    return tuple(
        _evidence(gate, match.group(3).strip(), _clean_path(match.group(1)), int(match.group(2)), text)
        for match in _MYPY.finditer(text)
    )


def _pyright(gate: Gate, text: str) -> tuple[Evidence, ...]:
    return tuple(
        _evidence(gate, match.group(3).strip(), _clean_path(match.group(1)), int(match.group(2)), text)
        for match in _PYRIGHT.finditer(text)
    )


def _ruff(gate: Gate, text: str) -> tuple[Evidence, ...]:
    return tuple(
        _evidence(
            gate,
            f"{match.group(3)} {match.group(4).strip()}",
            _clean_path(match.group(1)),
            int(match.group(2)),
            text,
        )
        for match in _RUFF.finditer(text)
    )


def _tsc(gate: Gate, text: str) -> tuple[Evidence, ...]:
    return tuple(
        _evidence(
            gate,
            f"{match.group(3)} {match.group(4).strip()}".strip(),
            _clean_path(match.group(1)),
            int(match.group(2)),
            text,
        )
        for match in _TSC.finditer(text)
    )


def _eslint(gate: Gate, text: str) -> tuple[Evidence, ...]:
    unix = tuple(
        _evidence(gate, match.group(3).strip(), _clean_path(match.group(1)), int(match.group(2)), text)
        for match in _ESLINT_UNIX.finditer(text)
    )
    if unix:
        return unix
    found: list[Evidence] = []
    current = ""
    for line in text.splitlines():
        file_match = _ESLINT_FILE.match(line)
        if file_match and not line[:1].isspace():
            current = file_match.group(1)
            continue
        hit = _ESLINT_STYLISH.match(line)
        if hit is None or not current:
            continue
        message = f"{hit.group(4)} {hit.group(3).strip()}".strip()
        found.append(_evidence(gate, message, _clean_path(current), int(hit.group(1)), text))
    return tuple(found)


def _js_tests(gate: Gate, text: str) -> tuple[Evidence, ...]:
    found: list[Evidence] = []
    for block in _FAIL_BLOCK.split(text):
        if not block.startswith("FAIL"):
            continue
        first = block.splitlines()[0]
        path_match = _FAIL_PATH.match(first)
        file = _clean_path(path_match.group(1)) if path_match else None
        line = _stack_line(block)
        bullets = [item.strip() for item in _BULLET.findall(block)]
        titles = bullets or [first.strip()]
        for title in titles:
            found.append(_evidence(gate, title, file, line, block))
    return tuple(found)


def _unknown(gate: Gate, text: str) -> tuple[Evidence, ...]:
    summary = next((line.strip() for line in text.splitlines() if line.strip()), f"{gate.name} failed")
    return (_evidence(gate, summary[:300], None, None, text),)


def _evidence(gate: Gate, summary: str, file: str | None, line: int | None, output: str) -> Evidence:
    return Evidence(
        kind=gate.kind,
        summary=summary,
        file=file,
        line=line,
        command=gate.command,
        output=output,
    )


def _combined(result: ExecResult) -> str:
    if result.stdout and result.stderr:
        return f"{result.stdout}\n{result.stderr}"
    return result.stdout or result.stderr


def _line_for(text: str, file: str) -> int | None:
    name = PurePosixPath(file).name
    last: int | None = None
    for match in _FILE_LINE.finditer(text):
        path = match.group(1).strip()
        if path.endswith(file) or path.endswith(name):
            last = int(match.group(2))
    return last


def _stack_line(block: str) -> int | None:
    match = _STACK_LINE.search(block)
    if match is None:
        return None
    return int(match.group(2))


def _clean_path(path: str) -> str:
    cleaned = path.strip().replace("\\", "/")
    if cleaned.startswith("./"):
        return cleaned[2:]
    return cleaned


_PARSERS = {
    "eslint": _eslint,
    "jest": _js_tests,
    "mypy": _mypy,
    "pyright": _pyright,
    "pytest": _pytest,
    "ruff": _ruff,
    "tsc": _tsc,
    "vitest": _js_tests,
}
