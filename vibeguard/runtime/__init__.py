"""Boot a detected web app and judge its runtime trace."""

from vibeguard.runtime.check import runtime_check
from vibeguard.runtime.detect import AppSpec, detect_app

__all__ = ["AppSpec", "detect_app", "runtime_check"]
