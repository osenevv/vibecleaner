"""Boot a detected web app and judge its runtime trace."""

from vibecleaner.runtime.check import runtime_check
from vibecleaner.runtime.detect import AppSpec, detect_app

__all__ = ["AppSpec", "detect_app", "runtime_check"]
