"""One project command the execution gate can run."""

from __future__ import annotations

from dataclasses import dataclass

from vibeguard.fix_contract import EvidenceKind


@dataclass(frozen=True)
class Gate:
    name: str
    kind: EvidenceKind
    command: tuple[str, ...]
    language: str
    alts: tuple[tuple[str, ...], ...] = ()

    def attempts(self) -> tuple[tuple[str, ...], ...]:
        """Primary spelling, then equivalent commands if that binary is missing."""
        return (self.command, *self.alts)
