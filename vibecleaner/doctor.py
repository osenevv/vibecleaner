"""Environment and repository diagnostics (`vibecleaner doctor`)."""

from __future__ import annotations

import json
import os
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path

from vibecleaner.project_rules import ProjectRulesError, load_project_rules
from vibecleaner.prompt_fix import resolve_agent_command
from vibecleaner.verify.sandbox import docker_unreachable_reason

_API_KEY_VARS: tuple[str, ...] = (
    "TYPESAFE_API_KEY",
    "GEMINI_API_KEY",
    "GOOGLE_API_KEY",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "PERPLEXITY_API_KEY",
    "LIQUID_API_KEY",
    "LAYA_BASE_URL",
    "VIBECLEANER_LOCAL_URL",
)
_AGENT_NAMES: tuple[str, ...] = ("claude", "codex", "gemini", "agy")


@dataclass(frozen=True)
class DoctorCheck:
    name: str
    status: str  # ok | warn | error
    detail: str
    hint: str = ""

    def to_dict(self) -> dict[str, str]:
        return {
            "name": self.name,
            "status": self.status,
            "detail": self.detail,
            "hint": self.hint,
        }


@dataclass(frozen=True)
class DoctorReport:
    root: Path
    checks: tuple[DoctorCheck, ...]

    @property
    def has_errors(self) -> bool:
        return any(check.status == "error" for check in self.checks)

    def to_dict(self) -> dict[str, object]:
        return {
            "root": str(self.root),
            "ok": not self.has_errors,
            "checks": [check.to_dict() for check in self.checks],
        }


def run_doctor(root: Path) -> DoctorReport:
    """Inspect runtime prerequisites, providers, agent CLIs, and repo configuration."""
    resolved = Path(root).expanduser().resolve()
    checks: list[DoctorCheck] = [
        _check_python(),
        _check_tool("git", "git", "Required for --diff, worktree repairs, and git hooks."),
        _check_tool("node", "node", "Optional; needed to run JS/TS tests (vitest/jest) and runtime checks."),
        _check_docker(),
        _check_providers(),
        _check_agents(),
        _check_repo_config(resolved),
    ]
    return DoctorReport(root=resolved, checks=tuple(checks))


def render_doctor_text(report: DoctorReport) -> str:
    lines = [f"VibeCleaner doctor ({report.root})", ""]
    for check in report.checks:
        tag = f"[{check.status.upper():5s}]"
        lines.append(f"  {tag} {check.name}: {check.detail}")
        if check.hint:
            lines.append(f"          -> {check.hint}")
    return "\n".join(lines)


def _check_python() -> DoctorCheck:
    ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    has_mon = hasattr(sys, "monitoring")
    if sys.version_info < (3, 11):
        return DoctorCheck("python", "error", f"Python {ver} (unsupported)", "Upgrade to Python 3.11+.")
    cov_mode = "sys.monitoring" if has_mon else "sys.settrace fallback"
    return DoctorCheck("python", "ok", f"Python {ver} ({cov_mode})")


def _check_tool(name: str, binary: str, hint: str) -> DoctorCheck:
    found = shutil.which(binary)
    if found:
        return DoctorCheck(name, "ok", found)
    status = "error" if name == "git" else "warn"
    return DoctorCheck(name, status, f"{binary} not found on PATH", hint)


def _check_docker() -> DoctorCheck:
    reason = docker_unreachable_reason()
    if reason is None:
        return DoctorCheck("docker", "ok", "daemon reachable")
    return DoctorCheck(
        "docker",
        "warn",
        reason,
        "Start Docker for isolated `vibecleaner start`, or pass `--sandbox host`.",
    )


def _check_providers() -> DoctorCheck:
    configured = [var for var in _API_KEY_VARS if os.environ.get(var)]
    if configured:
        return DoctorCheck("layer2-api", "ok", f"configured via {', '.join(configured)}")
    return DoctorCheck(
        "layer2-api",
        "warn",
        "no API key set (running offline heuristic judge)",
        "Set GEMINI_API_KEY (or OPENAI_API_KEY / TYPESAFE_API_KEY) for live Layer 2 checks.",
    )


def _check_agents() -> DoctorCheck:
    host = os.environ.get("VIBECLEANER_HOST", "").strip()
    installed = [name for name in _AGENT_NAMES if resolve_agent_command(name) is not None]
    parts: list[str] = []
    if host:
        parts.append(f"VIBECLEANER_HOST={host}")
    if installed:
        parts.append(f"CLIs: {', '.join(installed)}")
    if parts:
        return DoctorCheck("agents", "ok", "; ".join(parts))
    return DoctorCheck(
        "agents",
        "warn",
        "no coding agent CLI detected on PATH",
        "Install claude, codex, gemini, or agy (or set VIBECLEANER_HOST) for --autofix / fix host passes.",
    )


def _check_repo_config(root: Path) -> DoctorCheck:
    if not root.is_dir():
        return DoctorCheck("repo-config", "error", f"directory does not exist: {root}")
    try:
        rules = load_project_rules(root)
    except ProjectRulesError as exc:
        return DoctorCheck("repo-config", "error", f"invalid .vibecleaner/rules.json: {exc}")
    cfg_path = root / ".vibecleaner" / "config.json"
    if cfg_path.is_file():
        try:
            loaded = json.loads(cfg_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            return DoctorCheck("repo-config", "error", f"invalid .vibecleaner/config.json: {exc}")
        if not isinstance(loaded, dict):
            return DoctorCheck("repo-config", "error", ".vibecleaner/config.json must be a JSON object")
    details = [f"{len(rules.rules)} project rule(s)"]
    if cfg_path.is_file():
        details.append("config.json valid")
    if (root / ".vibecleanerignore").is_file():
        details.append(".vibecleanerignore present")
    return DoctorCheck("repo-config", "ok", ", ".join(details))
