"""Evidence builders shared by the runtime check."""

from __future__ import annotations

from vibecleaner.fix_contract import Evidence, EvidenceKind

RUNTIME_NODE = "runtime"


def note(summary: str) -> Evidence:
    return Evidence(EvidenceKind.JUDGE_NOTE, summary)


def traced(
    kind: EvidenceKind,
    summary: str,
    boot: tuple[str, ...],
    curl: tuple[str, ...],
    output: str,
    reproducer: str,
    file: str | None = None,
) -> Evidence:
    command = boot + ("--",) + curl if curl else boot
    return Evidence(
        kind,
        summary,
        file=file,
        command=command,
        output=output,
        reproducer=reproducer,
    )
