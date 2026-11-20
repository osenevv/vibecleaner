"""Static launch preflight. Reads code only; it does not call the network or a model."""

from vibeguard.preflight.engine import run_preflight
from vibeguard.preflight.render import preflight_to_json, render_preflight_markdown
from vibeguard.preflight.results import CheckResult, PreflightReport, Status
from vibeguard.preflight.signals import detect_stack, infer_summary

__all__ = [
    "CheckResult",
    "PreflightReport",
    "Status",
    "preflight_to_json",
    "render_preflight_markdown",
    "run_preflight",
]
