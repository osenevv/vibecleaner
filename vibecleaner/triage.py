"""Keep / Fix / Rebuild module triage and high-risk CODEOWNERS generation."""

from __future__ import annotations

import subprocess
from collections import Counter
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from vibecleaner.collector import _is_test_unit_path, collect
from vibecleaner.deterministic import run_deterministic
from vibecleaner.models import Category, Finding, Language, RiskTier, Severity

_CODE_LANGUAGES = frozenset(
    {Language.PYTHON, Language.TYPESCRIPT, Language.TSX, Language.JAVASCRIPT, Language.CSHARP, Language.SQL}
)
_DECISION_ORDER = {"rebuild": 0, "fix": 1, "keep": 2}
_RISK_ORDER = {RiskTier.HIGH: 0, RiskTier.MEDIUM: 1, RiskTier.LOW: 2}


@dataclass(frozen=True)
class ModuleTriage:
    path: str
    risk: RiskTier
    decision: str  # keep | fix | rebuild
    reason: str
    loc: int
    churn_90d: int
    security_hits: int
    slop_hits: int
    critical_hits: int

    def to_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "risk": self.risk.value,
            "decision": self.decision,
            "reason": self.reason,
            "loc": self.loc,
            "churn_90d": self.churn_90d,
            "security_hits": self.security_hits,
            "slop_hits": self.slop_hits,
            "critical_hits": self.critical_hits,
        }


@dataclass(frozen=True)
class TriageReport:
    root: Path
    modules: tuple[ModuleTriage, ...]

    @property
    def counts(self) -> dict[str, int]:
        counted = Counter(m.decision for m in self.modules)
        return {key: counted.get(key, 0) for key in ("rebuild", "fix", "keep")}

    @property
    def high_risk_paths(self) -> tuple[str, ...]:
        return tuple(sorted(m.path for m in self.modules if m.risk is RiskTier.HIGH))

    def to_dict(self) -> dict[str, object]:
        return {
            "root": str(self.root),
            "counts": self.counts,
            "high_risk_paths": list(self.high_risk_paths),
            "modules": [m.to_dict() for m in self.modules],
        }


def run_triage(root: Path, *, days: int = 90) -> TriageReport:
    """Classify every production module as Keep, Fix, or Rebuild from risk, findings, LOC, and git churn."""
    resolved = Path(root).expanduser().resolve()
    ctx = collect(resolved)
    findings = run_deterministic(ctx)
    by_file: dict[str, list[Finding]] = {}
    for finding in findings:
        by_file.setdefault(finding.file, []).append(finding)
    churn = _git_churn(resolved, days=days)

    from vibecleaner.risk import classify_file

    triaged: list[ModuleTriage] = []
    for sf in sorted(ctx.files, key=lambda item: item.path):
        if sf.language not in _CODE_LANGUAGES or _is_test_unit_path(sf.path):
            continue
        risk = classify_file(sf.path, sf.text)
        file_hits = by_file.get(sf.path, [])
        sec_hits = sum(1 for f in file_hits if f.category is Category.SECURITY)
        slop_hits = sum(1 for f in file_hits if f.category is Category.SLOP)
        crit_hits = sum(1 for f in file_hits if f.severity is Severity.CRITICAL)
        god = any(f.rule_id == "D6a.god_file" for f in file_hits)
        loc = sum(1 for line in sf.text.splitlines() if line.strip())
        touches = churn.get(sf.path, 0)
        decision, reason = _decide(risk, sec_hits, slop_hits, crit_hits, god, loc, touches)
        triaged.append(
            ModuleTriage(
                path=sf.path,
                risk=risk,
                decision=decision,
                reason=reason,
                loc=loc,
                churn_90d=touches,
                security_hits=sec_hits,
                slop_hits=slop_hits,
                critical_hits=crit_hits,
            )
        )

    triaged.sort(key=lambda m: (_DECISION_ORDER[m.decision], _RISK_ORDER[m.risk], -m.critical_hits, -m.slop_hits, m.path))
    return TriageReport(root=resolved, modules=tuple(triaged))


def _decide(
    risk: RiskTier,
    sec_hits: int,
    slop_hits: int,
    crit_hits: int,
    god: bool,
    loc: int,
    churn: int,
) -> tuple[str, str]:
    if risk is RiskTier.HIGH and (crit_hits > 0 or slop_hits >= 5) and (loc >= 300 or churn >= 5 or god):
        return "rebuild", "high-risk module with heavy debt/churn; redesign behind a clean interface"
    if god and (slop_hits >= 6 or churn >= 5):
        return "rebuild", "oversized god file with high slop or churn; split by bounded context"
    if crit_hits > 0 or sec_hits > 0:
        return "fix", f"{sec_hits} security finding(s) ({crit_hits} critical) require targeted hardening"
    if slop_hits > 0:
        return "fix", f"{slop_hits} slop/debt finding(s) eligible for incremental remediation"
    if risk is RiskTier.HIGH and churn >= 3:
        return "fix", "high-risk, high-churn module; prioritize characterization tests and review"
    return "keep", "clean static signals and bounded risk"


def generate_codeowners(report: TriageReport, owner: str) -> str:
    """Generate a ``.github/CODEOWNERS`` block protecting every high-risk path."""
    cleaned = owner.strip()
    if not cleaned:
        raise ValueError("CODEOWNERS owner handle cannot be empty")
    lines = [
        "# Generated by VibeCleaner triage — high-risk paths (auth, billing, crypto, migrations)",
        "",
    ]
    if not report.high_risk_paths:
        lines.append("# No high-risk paths detected.")
        return "\n".join(lines) + "\n"

    # Collapse directories that have 3+ high-risk files into a directory rule; list individual files otherwise.
    dir_counts: Counter[str] = Counter()
    for rel in report.high_risk_paths:
        parent = PurePosixPath(rel).parent.as_posix()
        if parent and parent != ".":
            dir_counts[parent] += 1

    collapsed_dirs = {d for d, count in dir_counts.items() if count >= 3}
    entries: list[str] = []
    seen: set[str] = set()
    for d in sorted(collapsed_dirs):
        pattern = f"/{d}/"
        if pattern not in seen:
            seen.add(pattern)
            entries.append(f"{pattern} {cleaned}")
    for rel in report.high_risk_paths:
        parent = PurePosixPath(rel).parent.as_posix()
        if parent in collapsed_dirs:
            continue
        pattern = f"/{rel}"
        if pattern not in seen:
            seen.add(pattern)
            entries.append(f"{pattern} {cleaned}")
    lines.extend(entries)
    return "\n".join(lines) + "\n"


def render_triage_markdown(report: TriageReport) -> str:
    counts = report.counts
    lines = [
        "# Keep / Fix / Rebuild Triage",
        "",
        f"- **Rebuild:** {counts['rebuild']} module(s)",
        f"- **Fix:** {counts['fix']} module(s)",
        f"- **Keep:** {counts['keep']} module(s)",
        f"- **High-risk paths (human sign-off):** {len(report.high_risk_paths)}",
        "",
        "| Decision | Risk | Module | LOC | 90d Churn | Security | Slop | Rationale |",
        "| --- | --- | --- | ---: | ---: | ---: | ---: | --- |",
    ]
    for mod in report.modules:
        lines.append(
            f"| **{mod.decision.upper()}** | {mod.risk.value} | `{mod.path}` | {mod.loc} | "
            f"{mod.churn_90d} | {mod.security_hits} | {mod.slop_hits} | {mod.reason} |"
        )
    lines.append("")
    return "\n".join(lines)


def _git_churn(root: Path, *, days: int) -> dict[str, int]:
    try:
        proc = subprocess.run(
            ["git", "log", f"--since={days}.days", "--name-only", "--pretty=format:"],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {}
    if proc.returncode != 0:
        return {}
    counts: Counter[str] = Counter()
    for line in proc.stdout.splitlines():
        rel = line.strip().replace("\\", "/")
        if rel:
            counts[rel] += 1
    return dict(counts)
