"""End-to-end scan: collect, Layer 1, Layer 2, optional fix drafts."""

from __future__ import annotations

import time
from pathlib import Path

from vibeguard.cache import DecisionCache
from vibeguard.decision_judge import judge, select_backend, units_to_skip
from vibeguard.models import DEFAULT_THRESHOLD, Finding, ScanContext, ScanResult
from vibeguard.patcher import generate_fixes


def run_scan(
    root: Path,
    diff_base: str | None = None,
    mode: str = "auto",
    threshold: float = DEFAULT_THRESHOLD,
    use_cache: bool = True,
    fix: bool = False,
) -> tuple[ScanResult, ScanContext]:
    """Collect the repo, run both layers, and return the sorted result plus context."""
    started = time.perf_counter()
    root = Path(root)
    # Deferred so importing the pipeline does not load the collector until a scan runs.
    from vibeguard.collector import collect
    from vibeguard.deterministic import run_deterministic

    ctx = collect(root, diff_base=diff_base)
    layer1 = list(run_deterministic(ctx))
    skip = units_to_skip(ctx.units, layer1)
    backend = select_backend(mode)
    cache = DecisionCache(
        root / ".vibeguard_cache.json",
        enabled=use_cache,
        model=backend.name if backend is not None else "disabled",
    )
    layer2, stats = judge(
        ctx,
        backend,
        cache,
        threshold=threshold,
        skip_unit_ids=skip,
    )
    cache.save()
    findings: list[Finding] = layer1 + layer2
    if fix:
        generate_fixes(findings, ctx)
    findings.sort(key=lambda finding: (-finding.severity.rank, finding.file, finding.line))
    result = ScanResult(
        root=ctx.root,
        findings=findings,
        files_scanned=len(ctx.files),
        judge=stats,
        duration_s=time.perf_counter() - started,
        diff_base=diff_base,
    )
    return result, ctx
