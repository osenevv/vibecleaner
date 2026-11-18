"""End-to-end scan: collect, Layer 1, Layer 2, optional fix drafts."""

from __future__ import annotations

import time
from pathlib import Path

from vibecleaner.cache import DecisionCache
from vibecleaner.decision_judge import judge, select_backend, units_to_skip
from vibecleaner.models import DEFAULT_THRESHOLD, PROJECT_RULE_PREFIX, RULES, Finding, ScanContext, ScanResult
from vibecleaner.patcher import generate_fixes
from vibecleaner.project_rules import apply_project_rules, load_project_rules
from vibecleaner.risk import route_review


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
    from vibecleaner.collector import collect
    from vibecleaner.deterministic import run_deterministic

    ctx = collect(root, diff_base=diff_base)
    project_rules = load_project_rules(ctx.root)
    layer1 = list(run_deterministic(ctx)) + apply_project_rules(project_rules, ctx.files)
    skip = units_to_skip(ctx.units, layer1)
    backend = select_backend(mode)
    cache = DecisionCache(
        root / ".vibecleaner_cache.json",
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
        review=route_review(ctx.files, findings, ctx.changed_files),
        project_rule_specs=tuple(
            RULES[PROJECT_RULE_PREFIX + rule.id] for rule in project_rules.rules
        ),
    )
    return result, ctx
