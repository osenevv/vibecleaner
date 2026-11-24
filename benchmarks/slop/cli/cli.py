"""Proof fixture: CLI with a holdout stub and lookalike logged catch."""

from __future__ import annotations

import logging
import sys

log = logging.getLogger(__name__)


def run_job(target: str) -> dict[str, object]:
    return {"status": "done", "count": 1}


def execute_job(target: str) -> dict[str, object]:
    try:
        return {"status": "done", "target": target}
    except ValueError as exc:
        log.warning("job failed: %s", exc)
        raise


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if not args:
        print("usage: cli <target>", file=sys.stderr)
        return 2
    print(execute_job(args[0]))
    return 0
