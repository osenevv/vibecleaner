"""Execution gate and tamper guard."""

from vibeguard.verify.gate import Gate
from vibeguard.verify.gates import detect_gates, run_gates
from vibeguard.verify.sandbox import DockerSandbox, HostSandbox, make_sandbox
from vibeguard.verify.snapshot import TamperSnapshot
from vibeguard.verify.tamper import check_tamper, snapshot

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
