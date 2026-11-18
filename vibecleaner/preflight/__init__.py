"""Static launch preflight. Reads code only; it does not call the network or a model."""

from vibecleaner.preflight.engine import run_preflight
from vibecleaner.preflight.render import preflight_to_json, render_preflight_markdown
from vibecleaner.preflight.results import CheckResult, PreflightReport, Status
from vibecleaner.preflight.signals import detect_stack, infer_summary

__all__ = [
    "CheckResult",
    "PreflightReport",
    "Status",
    "preflight_to_json",
    "render_preflight_markdown",
    "run_preflight",
]
