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
    blocked_locks = [machine for machine in extract_machines([blocked]) if machine.kind == "lock"]
    assert len(blocked_locks) == 1
    assert blocked_locks[0].line == 2
    assert [edge.target for edge in blocked_locks[0].transitions] == ["held", "free"]

    guarded_locks = [machine for machine in extract_machines([guarded]) if machine.kind == "lock"]
    assert len(guarded_locks) == 1
    assert guarded_locks[0].line == 2
    assert [edge.target for edge in guarded_locks[0].transitions] == ["held", "free"]


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


def test_typescript_while_true_retry_is_flagged_and_throw_is_not() -> None:
    spinning = _ts(
        "spin.ts",
        "function poll() {\n"
        "  while (true) {\n"
        "    try {\n"
        "      return fetch();\n"
        "    } catch (e) {\n"
        "      log();\n"
        "    }\n"
        "  }\n"
        "}\n",
    )
    hits = detect_state_bugs(spinning)
    assert [hit.rule_id for hit in hits] == ["D8.unbounded_retry"]
    assert hits[0].line == 2

    nested_parens = _ts(
        "parens.ts",
        "function poll() {\n"
        "  while ((true)) {\n"
        "    try { return fetch(); } catch (e) { log(); }\n"
        "  }\n"
        "}\n",
    )
    assert [hit.rule_id for hit in detect_state_bugs(nested_parens)] == ["D8.unbounded_retry"]

    bounded = _ts(
        "bounded.ts",
        "function poll(tries: number) {\n"
        "  while (true) {\n"
        "    try {\n"
        "      return fetch();\n"
        "    } catch (e) {\n"
        "      tries -= 1;\n"
        "      if (tries <= 0) throw e;\n"
        "    }\n"
        "  }\n"
        "}\n",
    )
    assert detect_state_bugs(bounded) == []


def test_typescript_lock_acquire_without_release_is_flagged() -> None:
    bare = _ts(
        "bare.ts",
        "async function run(mutex: Mutex) {\n"
        "  await mutex.acquire();\n"
        "  work();\n"
        "}\n",
    )
    hits = detect_state_bugs(bare)
    assert [hit.rule_id for hit in hits] == ["D8.lock_not_released"]
    assert "mutex.acquire" in (hits[0].snippet or "")

    released = _ts(
        "released.ts",
        "async function run(mutex: Mutex) {\n"
        "  await mutex.acquire();\n"
        "  try {\n"
        "    work();\n"
        "  } finally {\n"
        "    mutex.release();\n"
        "  }\n"
        "}\n",
    )
    assert detect_state_bugs(released) == []

    unlocked = _ts(
        "unlocked.ts",
        "async function run(mutex: Mutex) {\n"
        "  await mutex.lock();\n"
        "  try {\n"
        "    work();\n"
        "  } finally {\n"
        "    mutex.unlock();\n"
        "  }\n"
        "}\n",
    )
    assert detect_state_bugs(unlocked) == []

    disposed = _ts(
        "disposed.ts",
        "async function run(mutex: Mutex) {\n"
        "  using lock = await mutex.acquire();\n"
        "  work();\n"
        "}\n",
    )
    assert detect_state_bugs(disposed) == []


def test_nested_except_continue_does_not_mark_a_raising_retry_unbounded() -> None:
    nested = _py(
        "nested.py",
        "def poll():\n"
        "    while True:\n"
        "        try:\n"
        "            try:\n"
        "                return fetch()\n"
        "            except JSONDecodeError:\n"
        "                continue\n"
        "        except Exception:\n"
        "            raise\n",
    )
    assert detect_state_bugs(nested) == []
    retry = next(machine for machine in extract_machines([nested]) if machine.kind == "retry")
    assert retry.invariant == "A caught failure reaches raise, return, or break."

    spinning = _py(
        "spinning.py",
        "def poll():\n"
        "    while True:\n"
        "        try:\n"
        "            try:\n"
        "                return fetch()\n"
        "            except JSONDecodeError:\n"
        "                continue\n"
        "        except Exception:\n"
        "            log()\n",
    )
    assert [hit.rule_id for hit in detect_state_bugs(spinning)] == ["D8.unbounded_retry"]

    mixed = _py(
        "mixed.py",
        "def poll():\n"
        "    while True:\n"
        "        try:\n"
        "            return fetch()\n"
        "        except TimeoutError:\n"
        "            continue\n"
        "        except Exception:\n"
        "            raise\n",
    )
    assert detect_state_bugs(mixed) == []

    no_exit = _py(
        "no_exit.py",
        "def poll():\n"
        "    while True:\n"
        "        try:\n"
        "            return fetch()\n"
        "        except TimeoutError:\n"
        "            continue\n"
        "        except Exception:\n"
        "            log()\n",
    )
    assert [hit.rule_id for hit in detect_state_bugs(no_exit)] == ["D8.unbounded_retry"]


def test_each_acquire_is_paired_with_its_own_release() -> None:
    both = _py(
        "both.py",
        "def run(a, b):\n"
        "    a.acquire()\n"
        "    b.acquire()\n"
        "    try:\n"
        "        work()\n"
        "    finally:\n"
        "        a.release()\n",
    )
    hits = detect_state_bugs(both)
    assert [hit.rule_id for hit in hits] == ["D8.lock_not_released"]
    assert "b.acquire" in (hits[0].snippet or "")
    locks = [machine for machine in extract_machines([both]) if machine.kind == "lock"]
    assert [machine.line for machine in locks] == [2, 3]
    assert [len(machine.transitions) for machine in locks] == [2, 1]

    other = _py(
        "other.py",
        "def run(lock, other):\n"
        "    with other:\n"
        "        lock.acquire()\n"
        "        work()\n",
    )
    other_hits = detect_state_bugs(other)
    assert [hit.rule_id for hit in other_hits] == ["D8.lock_not_released"]
    assert "lock.acquire" in (other_hits[0].snippet or "")

    flock = _py(
        "flock.py",
        "def run(a, b):\n"
        "    a.acquire()\n"
        "    b.acquire()\n"
        "    try:\n"
        "        work()\n"
        "    finally:\n"
        "        fcntl.flock(a.fileno(), fcntl.LOCK_UN)\n",
    )
    flock_hits = detect_state_bugs(flock)
    assert [hit.rule_id for hit in flock_hits] == ["D8.lock_not_released"]
    assert "b.acquire" in (flock_hits[0].snippet or "")
