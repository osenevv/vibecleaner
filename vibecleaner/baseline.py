"""Ratchet baselines (.vibecleaner/baseline.json) and expired temporary-shim TTL detection."""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from vibecleaner.models import Finding, ScanResult, Severity
from vibecleaner.reporter import compute_scores

BASELINE_VERSION = 1
DEFAULT_BASELINE_REL = ".vibecleaner/baseline.json"


class BaselineError(ValueError):
    """Raised when a baseline file cannot be read or fails schema validation."""


@dataclass(frozen=True)
class BaselineSnapshot:
    version: int
    security_score: int
    slop_score: int
    findings_total: int
    by_severity: dict[str, int]
    fingerprints: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "version": self.version,
            "security_score": self.security_score,
            "slop_score": self.slop_score,
            "findings_total": self.findings_total,
            "by_severity": dict(self.by_severity),
            "fingerprints": list(self.fingerprints),
        }


@dataclass(frozen=True)
class BaselineDiff:
    new_findings: tuple[Finding, ...]
    resolved_count: int
    security_delta: int
    slop_delta: int

    @property
    def regressed(self) -> bool:
        return bool(self.new_findings) or self.security_delta < 0 or self.slop_delta < 0

    def to_dict(self) -> dict[str, object]:
        return {
            "regressed": self.regressed,
            "new_findings_count": len(self.new_findings),
            "resolved_count": self.resolved_count,
            "security_delta": self.security_delta,
            "slop_delta": self.slop_delta,
            "new_findings": [
                {
                    "rule_id": f.rule_id,
                    "severity": f.severity.value,
                    "file": f.file,
                    "line": f.line,
                    "message": f.message,
                }
                for f in self.new_findings
            ],
        }


def finding_fingerprint(finding: Finding) -> str:
    """Stable finding identity that survives minor line-number shifts when symbol is known."""
    anchor = finding.symbol or f"L{finding.line}"
    return f"{finding.rule_id}|{finding.file}|{anchor}"


def snapshot_from_result(result: ScanResult) -> BaselineSnapshot:
    counts = Counter(f.severity.value for f in result.findings)
    by_sev = {sev.value: counts.get(sev.value, 0) for sev in Severity}
    fps = tuple(sorted(finding_fingerprint(f) for f in result.findings))
    sec_score, slop_score = compute_scores(result.findings)
    return BaselineSnapshot(
        version=BASELINE_VERSION,
        security_score=sec_score,
        slop_score=slop_score,
        findings_total=len(result.findings),
        by_severity=by_sev,
        fingerprints=fps,
    )


def save_baseline(result: ScanResult, path: Path) -> Path:
    dest = Path(path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    snap = snapshot_from_result(result)
    dest.write_text(json.dumps(snap.to_dict(), indent=2) + "\n", encoding="utf-8")
    return dest


def load_baseline(path: Path) -> BaselineSnapshot:
    src = Path(path)
    if not src.is_file():
        raise BaselineError(f"baseline file not found: {src}")
    try:
        raw = json.loads(src.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BaselineError(f"invalid baseline file {src}: {exc}") from exc
    if not isinstance(raw, dict) or raw.get("version") != BASELINE_VERSION:
        raise BaselineError(f"invalid baseline version in {src}: expected {BASELINE_VERSION}")
    sec = raw.get("security_score")
    slop = raw.get("slop_score")
    total = raw.get("findings_total")
    by_sev = raw.get("by_severity")
    fps = raw.get("fingerprints")
    if (
        not isinstance(sec, int)
        or not isinstance(slop, int)
        or not isinstance(total, int)
        or not isinstance(by_sev, dict)
        or not isinstance(fps, list)
        or not all(isinstance(item, str) for item in fps)
    ):
        raise BaselineError(f"malformed baseline schema in {src}")
    return BaselineSnapshot(
        version=BASELINE_VERSION,
        security_score=sec,
        slop_score=slop,
        findings_total=total,
        by_severity={str(k): int(v) for k, v in by_sev.items() if isinstance(v, int)},
        fingerprints=tuple(fps),
    )


def compare_baseline(result: ScanResult, baseline: BaselineSnapshot, *, fail_on: str = "high") -> BaselineDiff:
    """Compare ``result`` against ``baseline`` using multiset fingerprint diffing."""
    remaining = Counter(baseline.fingerprints)
    new_all: list[Finding] = []
    for finding in result.findings:
        fp = finding_fingerprint(finding)
        if remaining[fp] > 0:
            remaining[fp] -= 1
        else:
            new_all.append(finding)
    if fail_on == "none":
        new_filtered: list[Finding] = []
    else:
        cutoff = Severity(fail_on).rank
        new_filtered = [f for f in new_all if f.severity.rank >= cutoff]
    resolved = sum(remaining.values())
    sec_score, slop_score = compute_scores(result.findings)
    return BaselineDiff(
        new_findings=tuple(new_filtered),
        resolved_count=resolved,
        security_delta=sec_score - baseline.security_score,
        slop_delta=slop_score - baseline.slop_score,
    )
