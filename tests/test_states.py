"""State-machine extraction and the transitions a function can fail to finish."""

from __future__ import annotations

from pathlib import Path

from vibeguard.cli import main
from vibeguard.models import Language
from vibeguard.states import detect_state_bugs, extract_machines, render_states
from vibeguard.models import SourceFile


def _py(name: str, text: str) -> SourceFile:
    return SourceFile(path=name, abs_path=Path(name), language=Language.PYTHON, text=text)


def _ts(name: str, text: str) -> SourceFile:
    return SourceFile(path=name, abs_path=Path(name), language=Language.TYPESCRIPT, text=text)


def test_unbounded_retry_is_flagged_and_a_bounded_one_is_not() -> None:
    spinning = _py(
        "spin.py",
        "def poll():\n"
        "    while True:\n"
        "        try:\n"
        "            return fetch()\n"
        "        except Exception:\n"
        "            log()\n",
    )
    hits = detect_state_bugs(spinning)
    assert [hit.rule_id for hit in hits] == ["D8.unbounded_retry"]
    assert hits[0].severity.value == "high"

    bounded = _py(
        "bounded.py",
        "def poll(tries):\n"
        "    while True:\n"
        "        try:\n"
        "            return fetch()\n"
        "        except Exception:\n"
        "            tries -= 1\n"
        "            if tries <= 0:\n"
        "                raise\n",
    )
    assert detect_state_bugs(bounded) == []


def test_retry_that_falls_through_is_flagged_and_a_final_raise_is_not() -> None:
    silent = _py(
        "silent.py",
        "def fetch():\n"
        "    for attempt in range(3):\n"
        "        try:\n"
        "            return call()\n"
        "        except Exception:\n"
        "            log(attempt)\n",
    )
    assert [hit.rule_id for hit in detect_state_bugs(silent)] == ["D8.retry_falls_through"]

    closed = _py(
        "closed.py",
        "def fetch():\n"
        "    last = None\n"
        "    for attempt in range(3):\n"
        "        try:\n"
        "            return call()\n"
        "        except Exception as exc:\n"
        "            last = exc\n"
        "    raise last\n",
    )
    assert detect_state_bugs(closed) == []
    machines = extract_machines([closed])
    assert any(machine.kind == "retry" for machine in machines)


def test_lock_acquire_without_release_is_flagged() -> None:
    bare = _py(
        "bare.py",
        "def run(lock):\n"
        "    lock.acquire()\n"
        "    work()\n",
    )
    hits = detect_state_bugs(bare)
    assert [hit.rule_id for hit in hits] == ["D8.lock_not_released"]

    guarded = _py(
        "guarded.py",
        "def run(lock):\n"
        "    lock.acquire()\n"
        "    try:\n"
        "        work()\n"
        "    finally:\n"
        "        lock.release()\n",
    )
    assert detect_state_bugs(guarded) == []

    blocked = _py(
        "blocked.py",
        "def run(lock):\n"
        "    with lock:\n"
        "        lock.acquire()\n"
        "        work()\n",
    )
    assert detect_state_bugs(blocked) == []


def test_enum_and_union_become_transition_tables() -> None:
    source = _py(
        "mode.py",
        "from enum import Enum\n"
        "class Mode(Enum):\n"
        "    OPEN = 'open'\n"
        "    SHUT = 'shut'\n",
    )
    machines = extract_machines([source])
    assert machines[0].name == "Mode"
    assert machines[0].states == ["OPEN", "SHUT"]
    text = render_states(machines, [])
    assert "| `caller` | set OPEN | `OPEN` |" in text
    assert "Confirmed invalid transitions" in text
    assert "None." in text

    union = _ts("mode.ts", 'type Mode = "open" | "shut"\n')
    unions = extract_machines([union])
    assert unions[0].states == ["open", "shut"]


def test_states_command_writes_the_file_and_fails_on_a_spin(tmp_path: Path, capsys) -> None:
    (tmp_path / "spin.py").write_text(
        "def poll():\n"
        "    while True:\n"
        "        try:\n"
        "            return fetch()\n"
        "        except Exception:\n"
        "            log()\n",
        encoding="utf-8",
    )
    assert main(["states", str(tmp_path), "--out", str(tmp_path / "OUT.md")]) == 1
    body = (tmp_path / "OUT.md").read_text(encoding="utf-8")
    assert "D8.unbounded_retry" in body
    assert "poll retry" in body
    assert "wrote" in capsys.readouterr().out
