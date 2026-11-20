"""Score VibeGuard benchmark cases against benchmarks/labels.json."""

from __future__ import annotations

import argparse
import fnmatch
import json
import math
import sys
import time
import traceback
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

BENCHMARKS = REPO_ROOT / "benchmarks"
DETECTORS: tuple[str, ...] = ("D1", "D2", "D3", "D4", "D5", "D6a", "D6b", "D7a", "D7b")
LAYER1 = frozenset({"D1", "D2", "D6a"})
LAYER2 = frozenset({"D3", "D4", "D5", "D6b", "D7a", "D7b"})
COST_PER_MILLION_INPUT = 0.10


@dataclass(frozen=True)
class CaseSpec:
    case_id: str
    kind: str
    path: Path
    expected: tuple[str, ...]
    why: str


@dataclass
class Observation:
    spec: CaseSpec
    findings: list[tuple[str, float | None]]
    latency_s: float
    input_tokens: int
    mode: str


@dataclass
class Counts:
    tp: int = 0
    fp: int = 0
    fn: int = 0

    def add(self, other: Counts) -> None:
        self.tp += other.tp
        self.fp += other.fp
        self.fn += other.fn


@dataclass
class CaseScore:
    case_id: str
    kind: str
    expected: tuple[str, ...]
    predicted: tuple[str, ...]
    false_positives: tuple[str, ...]
    false_negatives: tuple[str, ...]
    mark: str
    latency_s: float


@dataclass
class ThresholdReport:
    threshold: float
    post_filtered: bool
    counts: Counts
    per_detector: dict[str, Counts]
    per_layer: dict[str, Counts]
    cases: list[CaseScore]
    negative_cases: int
    negative_flagged: int


@dataclass
class EvalReport:
    generated_at: str
    mode_requested: str
    modes_observed: list[str]
    scan_threshold: float
    primary: ThresholdReport
    sweep: list[ThresholdReport] = field(default_factory=list)
    latency_s: list[float] = field(default_factory=list)
    input_tokens: int = 0


def sort_detectors(ids: Iterable[str]) -> tuple[str, ...]:
    present = set(ids)
    known = [detector for detector in DETECTORS if detector in present]
    extra = sorted(present.difference(DETECTORS))
    return tuple(known + extra)


def ratio(numerator: int, denominator: int) -> float | None:
    if denominator == 0:
        return None
    return numerator / denominator


def f1_score(precision: float | None, recall: float | None) -> float | None:
    if precision is None or recall is None:
        return None
    if precision + recall == 0:
        return 0.0
    return 2 * precision * recall / (precision + recall)


def fmt_ratio(value: float | None) -> str:
    if value is None:
        return "n/a"
    return f"{value:.3f}"


def fmt_set(ids: Sequence[str]) -> str:
    if not ids:
        return "—"
    return ",".join(ids)


def percentile(values: Sequence[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    rank = (len(ordered) - 1) * fraction
    low = math.floor(rank)
    high = math.ceil(rank)
    if low == high:
        return ordered[low]
    weight = rank - low
    return ordered[low] * (1 - weight) + ordered[high] * weight


def load_cases(benchmarks: Path) -> list[CaseSpec]:
    payload = json.loads((benchmarks / "labels.json").read_text(encoding="utf-8"))
    raw_cases = payload.get("cases")
    if not isinstance(raw_cases, dict):
        raise RuntimeError("labels.json is missing a cases object")
    specs: list[CaseSpec] = []
    found: set[str] = set()
    for kind in ("positive", "negative"):
        folder = benchmarks / kind
        if not folder.is_dir():
            raise RuntimeError(f"missing benchmark directory {folder}")
        for path in sorted(item for item in folder.iterdir() if item.is_dir()):
            case_id = f"{kind}/{path.name}"
            found.add(case_id)
            entry = raw_cases.get(case_id)
            if not isinstance(entry, dict) or "expected" not in entry:
                raise RuntimeError(f"labels.json has no expected list for {case_id}")
            expected_raw = entry["expected"]
            if not isinstance(expected_raw, list) or not all(isinstance(item, str) for item in expected_raw):
                raise RuntimeError(f"{case_id} expected must be a list of detector ids")
            unknown = [item for item in expected_raw if item not in DETECTORS]
            if unknown:
                raise RuntimeError(f"{case_id} has unknown detectors {unknown}")
            expected = sort_detectors(expected_raw)
            if kind == "negative" and expected:
                raise RuntimeError(f"{case_id} is a negative case and must expect no detectors")
            if kind == "positive" and not expected:
                raise RuntimeError(f"{case_id} is a positive case and must expect a detector")
            why = entry.get("why", "")
            if not isinstance(why, str):
                raise RuntimeError(f"{case_id} why must be a string")
            specs.append(CaseSpec(case_id, kind, path, expected, why))
    extra = sorted(set(raw_cases).difference(found))
    missing = sorted(found.difference(raw_cases))
    if extra or missing:
        raise RuntimeError(f"labels.json does not match case directories extra={extra} missing={missing}")
    return specs


def select_cases(cases: Sequence[CaseSpec], pattern: str | None) -> list[CaseSpec]:
    if pattern is None:
        return list(cases)
    chosen = [
        case
        for case in cases
        if fnmatch.fnmatch(case.case_id, pattern) or fnmatch.fnmatch(case.case_id.split("/", 1)[1], pattern)
    ]
    if not chosen:
        raise RuntimeError(f"no cases matched {pattern!r}")
    return chosen


def load_scanner():
    try:
        from vibeguard.pipeline import run_scan
    except ImportError as exc:
        raise RuntimeError(
            "could not import vibeguard.pipeline.run_scan "
            f"({exc}). Expected run_scan(root, diff_base=None, mode='auto', "
            "threshold=0.75, use_cache=False, fix=False) -> tuple[ScanResult, ScanContext]."
        ) from exc
    return run_scan


def scan_case(run_scan, case: CaseSpec, mode: str, threshold: float) -> Observation:
    started = time.perf_counter()
    scanned = run_scan(
        case.path,
        diff_base=None,
        mode=mode,
        threshold=threshold,
        use_cache=False,
        fix=False,
    )
    elapsed = time.perf_counter() - started
    if not isinstance(scanned, tuple) or len(scanned) != 2:
        raise TypeError(f"{case.case_id}: run_scan must return (ScanResult, ScanContext)")
    result, _context = scanned
    findings: list[tuple[str, float | None]] = []
    for finding in result.findings:
        probability = None if finding.probability is None else float(finding.probability)
        findings.append((str(finding.detector), probability))
    return Observation(
        spec=case,
        findings=findings,
        latency_s=elapsed,
        input_tokens=int(result.judge.input_tokens),
        mode=str(result.judge.mode),
    )


def predicted_detectors(obs: Observation, threshold: float, post_filter: bool) -> tuple[str, ...]:
    chosen: list[str] = []
    for detector, probability in obs.findings:
        if post_filter and probability is not None and probability < threshold:
            continue
        chosen.append(detector)
    return sort_detectors(chosen)


def case_mark(expected: Sequence[str], predicted: Sequence[str]) -> tuple[tuple[str, ...], tuple[str, ...], str]:
    exp = set(expected)
    pred = set(predicted)
    false_positives = sort_detectors(pred - exp)
    false_negatives = sort_detectors(exp - pred)
    parts: list[str] = []
    if false_positives:
        parts.append("FP " + ",".join(false_positives))
    if false_negatives:
        parts.append("FN " + ",".join(false_negatives))
    return false_positives, false_negatives, "ok" if not parts else "; ".join(parts)


def score(observations: Sequence[Observation], threshold: float, post_filter: bool) -> ThresholdReport:
    per_detector = {detector: Counts() for detector in DETECTORS}
    cases: list[CaseScore] = []
    negative_cases = 0
    negative_flagged = 0
    for obs in observations:
        predicted = predicted_detectors(obs, threshold, post_filter)
        false_positives, false_negatives, mark = case_mark(obs.spec.expected, predicted)
        if obs.spec.kind == "negative":
            negative_cases += 1
            if predicted:
                negative_flagged += 1
        expected_set = set(obs.spec.expected)
        predicted_set = set(predicted)
        for detector in expected_set & predicted_set:
            bucket = per_detector.setdefault(detector, Counts())
            bucket.tp += 1
        for detector in predicted_set - expected_set:
            bucket = per_detector.setdefault(detector, Counts())
            bucket.fp += 1
        for detector in expected_set - predicted_set:
            bucket = per_detector.setdefault(detector, Counts())
            bucket.fn += 1
        cases.append(
            CaseScore(
                case_id=obs.spec.case_id,
                kind=obs.spec.kind,
                expected=obs.spec.expected,
                predicted=predicted,
                false_positives=false_positives,
                false_negatives=false_negatives,
                mark=mark,
                latency_s=obs.latency_s,
            )
        )
    totals = Counts()
    for counts in per_detector.values():
        totals.add(counts)
    per_layer = {
        "layer1": _sum_detectors(per_detector, LAYER1),
        "layer2": _sum_detectors(per_detector, LAYER2),
    }
    return ThresholdReport(
        threshold=threshold,
        post_filtered=post_filter,
        counts=totals,
        per_detector=per_detector,
        per_layer=per_layer,
        cases=cases,
        negative_cases=negative_cases,
        negative_flagged=negative_flagged,
    )


def _sum_detectors(per_detector: dict[str, Counts], wanted: frozenset[str]) -> Counts:
    total = Counts()
    for detector, counts in per_detector.items():
        if detector in wanted:
            total.add(counts)
    return total


def metric_row(counts: Counts) -> dict[str, float | int | None]:
    precision = ratio(counts.tp, counts.tp + counts.fp)
    recall = ratio(counts.tp, counts.tp + counts.fn)
    return {
        "tp": counts.tp,
        "fp": counts.fp,
        "fn": counts.fn,
        "precision": precision,
        "recall": recall,
        "f1": f1_score(precision, recall),
    }


def false_positive_rate(report: ThresholdReport) -> float | None:
    return ratio(report.negative_flagged, report.negative_cases)


def render_markdown(report: EvalReport) -> str:
    lines: list[str] = [
        "# VibeGuard benchmark",
        "",
        f"- Timestamp: {report.generated_at}",
        f"- Mode requested: {report.mode_requested}",
        f"- Mode observed: {', '.join(report.modes_observed) if report.modes_observed else 'n/a'}",
        f"- Scan threshold: {report.scan_threshold:.2f}",
        f"- Report threshold: {report.primary.threshold:.2f}",
        f"- Cases: {len(report.primary.cases)}",
        f"- Input tokens: {report.input_tokens}",
        f"- Estimated cost: ${report.input_tokens / 1_000_000 * COST_PER_MILLION_INPUT:.6f} at $0.10 / 1M input tokens",
        "",
    ]
    if report.sweep:
        lines.append("Sweep rows re-threshold one scan taken at the lowest cutoff. Findings with probability null always count.")
        lines.append("")
        lines.extend(_summary_table([report.primary] if not report.sweep else report.sweep))
        lines.append("")
    lines.append(f"## Metrics at {report.primary.threshold:.2f}")
    lines.append("")
    lines.extend(_counts_table(report.primary))
    lines.append("")
    lines.append("## Per detector")
    lines.append("")
    lines.extend(_detector_table(report.primary))
    lines.append("")
    lines.append("## Per layer")
    lines.append("")
    lines.extend(_layer_table(report.primary))
    lines.append("")
    lines.append("## Latency")
    lines.append("")
    lines.append(_latency_line(report.latency_s))
    lines.append("")
    lines.append("## Per case")
    lines.append("")
    lines.extend(_case_table(report.primary))
    lines.append("")
    return "\n".join(lines)


def _summary_table(reports: Sequence[ThresholdReport]) -> list[str]:
    header = "| threshold | precision | recall | f1 | fpr | tp | fp | fn |"
    align = "| --- | --- | --- | --- | --- | --- | --- | --- |"
    rows = [header, align]
    for item in reports:
        metrics = metric_row(item.counts)
        rows.append(
            "| {threshold:.2f} | {precision} | {recall} | {f1} | {fpr} | {tp} | {fp} | {fn} |".format(
                threshold=item.threshold,
                precision=fmt_ratio(metrics["precision"] if isinstance(metrics["precision"], float) or metrics["precision"] is None else None),
                recall=fmt_ratio(metrics["recall"] if isinstance(metrics["recall"], float) or metrics["recall"] is None else None),
                f1=fmt_ratio(metrics["f1"] if isinstance(metrics["f1"], float) or metrics["f1"] is None else None),
                fpr=fmt_ratio(false_positive_rate(item)),
                tp=item.counts.tp,
                fp=item.counts.fp,
                fn=item.counts.fn,
            )
        )
    return rows


def _counts_table(report: ThresholdReport) -> list[str]:
    metrics = metric_row(report.counts)
    return [
        "| precision | recall | f1 | fpr | tp | fp | fn |",
        "| --- | --- | --- | --- | --- | --- | --- |",
        "| {precision} | {recall} | {f1} | {fpr} | {tp} | {fp} | {fn} |".format(
            precision=fmt_ratio(_as_optional_float(metrics["precision"])),
            recall=fmt_ratio(_as_optional_float(metrics["recall"])),
            f1=fmt_ratio(_as_optional_float(metrics["f1"])),
            fpr=fmt_ratio(false_positive_rate(report)),
            tp=report.counts.tp,
            fp=report.counts.fp,
            fn=report.counts.fn,
        ),
    ]


def _as_optional_float(value: object) -> float | None:
    if value is None or isinstance(value, float):
        return value
    return None


def _detector_table(report: ThresholdReport) -> list[str]:
    rows = [
        "| detector | tp | fp | fn | precision | recall | f1 |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    detectors = list(DETECTORS) + [item for item in report.per_detector if item not in DETECTORS]
    for detector in detectors:
        metrics = metric_row(report.per_detector[detector])
        rows.append(
            f"| {detector} | {metrics['tp']} | {metrics['fp']} | {metrics['fn']} | "
            f"{fmt_ratio(_as_optional_float(metrics['precision']))} | "
            f"{fmt_ratio(_as_optional_float(metrics['recall']))} | "
            f"{fmt_ratio(_as_optional_float(metrics['f1']))} |"
        )
    return rows


def _layer_table(report: ThresholdReport) -> list[str]:
    rows = [
        "| layer | detectors | tp | fp | fn | precision | recall | f1 |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    labels = {"layer1": "D1 D2 D6a", "layer2": "D3 D4 D5 D6b D7a D7b"}
    for key in ("layer1", "layer2"):
        metrics = metric_row(report.per_layer[key])
        rows.append(
            f"| {key} | {labels[key]} | {metrics['tp']} | {metrics['fp']} | {metrics['fn']} | "
            f"{fmt_ratio(_as_optional_float(metrics['precision']))} | "
            f"{fmt_ratio(_as_optional_float(metrics['recall']))} | "
            f"{fmt_ratio(_as_optional_float(metrics['f1']))} |"
        )
    return rows


def _latency_line(values: Sequence[float]) -> str:
    if not values:
        return "No cases were scanned."
    mean = sum(values) / len(values)
    return (
        f"mean {mean:.4f}s, p50 {percentile(values, 0.50):.4f}s, "
        f"p95 {percentile(values, 0.95):.4f}s over {len(values)} cases"
    )


def _case_table(report: ThresholdReport) -> list[str]:
    rows = [
        "| case | expected | predicted | result | latency |",
        "| --- | --- | --- | --- | --- |",
    ]
    for case in report.cases:
        rows.append(
            f"| {case.case_id} | {fmt_set(case.expected)} | {fmt_set(case.predicted)} | "
            f"{case.mark} | {case.latency_s:.4f}s |"
        )
    return rows


def report_dict(report: EvalReport) -> dict[str, object]:
    return {
        "generated_at": report.generated_at,
        "mode_requested": report.mode_requested,
        "modes_observed": report.modes_observed,
        "scan_threshold": report.scan_threshold,
        "threshold": report.primary.threshold,
        "input_tokens": report.input_tokens,
        "estimated_cost_usd": report.input_tokens / 1_000_000 * COST_PER_MILLION_INPUT,
        "latency_s": {
            "mean": (sum(report.latency_s) / len(report.latency_s)) if report.latency_s else 0.0,
            "p50": percentile(report.latency_s, 0.50),
            "p95": percentile(report.latency_s, 0.95),
            "per_case": {case.case_id: case.latency_s for case in report.primary.cases},
        },
        "summary": _public_summary(report.primary),
        "per_detector": {detector: metric_row(counts) for detector, counts in report.primary.per_detector.items()},
        "per_layer": {name: metric_row(counts) for name, counts in report.primary.per_layer.items()},
        "per_case": [_public_case(case) for case in report.primary.cases],
        "sweep": [_public_summary(item) | {"threshold": item.threshold} for item in report.sweep],
    }


def _public_summary(report: ThresholdReport) -> dict[str, object]:
    metrics = metric_row(report.counts)
    metrics["fpr"] = false_positive_rate(report)
    metrics["negative_cases"] = report.negative_cases
    metrics["negative_flagged"] = report.negative_flagged
    return metrics


def _public_case(case: CaseScore) -> dict[str, object]:
    return {
        "id": case.case_id,
        "kind": case.kind,
        "expected": list(case.expected),
        "predicted": list(case.predicted),
        "fp": list(case.false_positives),
        "fn": list(case.false_negatives),
        "mark": case.mark,
        "latency_s": case.latency_s,
    }


def emit_console(report: EvalReport) -> None:
    try:
        from rich.console import Console
        from rich.table import Table
    except ImportError:
        print(render_markdown(report))
        return
    console = Console()
    modes = ", ".join(report.modes_observed) if report.modes_observed else "n/a"
    console.print(
        f"VibeGuard eval  mode={report.mode_requested} observed={modes}  "
        f"threshold={report.primary.threshold:.2f}  cases={len(report.primary.cases)}"
    )
    summary = Table(title="Metrics")
    for column in ("precision", "recall", "f1", "fpr", "tp", "fp", "fn"):
        summary.add_column(column)
    metrics = metric_row(report.primary.counts)
    summary.add_row(
        fmt_ratio(_as_optional_float(metrics["precision"])),
        fmt_ratio(_as_optional_float(metrics["recall"])),
        fmt_ratio(_as_optional_float(metrics["f1"])),
        fmt_ratio(false_positive_rate(report.primary)),
        str(report.primary.counts.tp),
        str(report.primary.counts.fp),
        str(report.primary.counts.fn),
    )
    console.print(summary)
    detectors = Table(title="Per detector")
    for column in ("detector", "tp", "fp", "fn", "precision", "recall", "f1"):
        detectors.add_column(column)
    order = list(DETECTORS) + [item for item in report.primary.per_detector if item not in DETECTORS]
    for detector in order:
        row = metric_row(report.primary.per_detector[detector])
        detectors.add_row(
            detector,
            str(row["tp"]),
            str(row["fp"]),
            str(row["fn"]),
            fmt_ratio(_as_optional_float(row["precision"])),
            fmt_ratio(_as_optional_float(row["recall"])),
            fmt_ratio(_as_optional_float(row["f1"])),
        )
    console.print(detectors)
    layers = Table(title="Per layer")
    for column in ("layer", "tp", "fp", "fn", "precision", "recall", "f1"):
        layers.add_column(column)
    for name in ("layer1", "layer2"):
        row = metric_row(report.primary.per_layer[name])
        layers.add_row(
            name,
            str(row["tp"]),
            str(row["fp"]),
            str(row["fn"]),
            fmt_ratio(_as_optional_float(row["precision"])),
            fmt_ratio(_as_optional_float(row["recall"])),
            fmt_ratio(_as_optional_float(row["f1"])),
        )
    console.print(layers)
    console.print(_latency_line(report.latency_s))
    console.print(
        f"input tokens {report.input_tokens}  "
        f"estimated cost ${report.input_tokens / 1_000_000 * COST_PER_MILLION_INPUT:.6f}"
    )
    if report.sweep:
        sweep = Table(title="Threshold sweep")
        for column in ("threshold", "precision", "recall", "f1", "fpr", "tp", "fp", "fn"):
            sweep.add_column(column)
        for item in report.sweep:
            row = metric_row(item.counts)
            sweep.add_row(
                f"{item.threshold:.2f}",
                fmt_ratio(_as_optional_float(row["precision"])),
                fmt_ratio(_as_optional_float(row["recall"])),
                fmt_ratio(_as_optional_float(row["f1"])),
                fmt_ratio(false_positive_rate(item)),
                str(item.counts.tp),
                str(item.counts.fp),
                str(item.counts.fn),
            )
        console.print(sweep)
    cases = Table(title="Per case")
    for column in ("case", "expected", "predicted", "result", "s"):
        cases.add_column(column)
    for case in report.primary.cases:
        cases.add_row(
            case.case_id,
            fmt_set(case.expected),
            fmt_set(case.predicted),
            case.mark,
            f"{case.latency_s:.4f}",
        )
    console.print(cases)


def parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Score VibeGuard against the benchmark cases.")
    parser.add_argument("--mode", choices=("auto", "live", "offline", "off"), default="auto")
    parser.add_argument("--threshold", type=float, default=0.75)
    parser.add_argument("--sweep", default=None, help="Comma-separated thresholds, lowest is scanned once.")
    parser.add_argument("--cases", default=None, help="Glob matched against positive/name or the directory name.")
    parser.add_argument("--write-results", default=None, help="Write the markdown report to this path.")
    parser.add_argument("--json", dest="dump_json", action="store_true")
    return parser.parse_args(argv)


def parse_sweep(raw: str) -> list[float]:
    parts = [part.strip() for part in raw.split(",") if part.strip()]
    if not parts:
        raise ValueError("sweep list is empty")
    return [float(part) for part in parts]


def build_report(
    observations: Sequence[Observation],
    mode: str,
    threshold: float,
    scan_threshold: float,
    sweep: list[float] | None,
) -> EvalReport:
    if sweep:
        scored = [score(observations, item, post_filter=True) for item in sweep]
        primary = next(item for item in scored if math.isclose(item.threshold, threshold))
        sweep_reports = scored
    else:
        primary = score(observations, threshold, post_filter=False)
        sweep_reports = []
    modes = sorted({obs.mode for obs in observations})
    return EvalReport(
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        mode_requested=mode,
        modes_observed=modes,
        scan_threshold=scan_threshold,
        primary=primary,
        sweep=sweep_reports,
        latency_s=[obs.latency_s for obs in observations],
        input_tokens=sum(obs.input_tokens for obs in observations),
    )


def run(argv: Sequence[str] | None = None) -> EvalReport:
    args = parse_args(argv)
    if args.sweep:
        sweep = sorted(set(parse_sweep(args.sweep)) | {args.threshold})
        scan_threshold = min(sweep)
    else:
        sweep = None
        scan_threshold = args.threshold
    cases = select_cases(load_cases(BENCHMARKS), args.cases)
    run_scan = load_scanner()
    observations = [scan_case(run_scan, case, args.mode, scan_threshold) for case in cases]
    return build_report(observations, args.mode, args.threshold, scan_threshold, sweep)


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = parse_args(argv)
        report = run(argv)
    except Exception:
        traceback.print_exc(file=sys.stderr)
        print("error: benchmark aborted because the scanner raised", file=sys.stderr)
        return 2
    markdown = render_markdown(report)
    if args.write_results:
        destination = Path(args.write_results)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(markdown, encoding="utf-8")
    if args.dump_json:
        json.dump(report_dict(report), sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        emit_console(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
