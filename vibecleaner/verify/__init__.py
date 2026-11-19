"""Execution gate and tamper guard."""

from vibecleaner.verify.gate import Gate
from vibecleaner.verify.gates import detect_gates, run_gates
from vibecleaner.verify.sandbox import DockerSandbox, HostSandbox, make_sandbox
from vibecleaner.verify.snapshot import TamperSnapshot
from vibecleaner.verify.tamper import check_tamper, snapshot

__all__ = [
    "DockerSandbox",
    "Gate",
    "HostSandbox",
    "TamperSnapshot",
    "check_tamper",
    "detect_gates",
    "make_sandbox",
    "run_gates",
    "snapshot",
]
