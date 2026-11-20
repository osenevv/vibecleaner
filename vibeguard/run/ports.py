"""Call sibling packages when they exist, and the local fallback until they do."""

from __future__ import annotations

import importlib
from collections.abc import Mapping
from pathlib import Path

from vibeguard.fix_contract import CheckResult, FixContext, Sandbox, Team, Verdict

MISSING_TEAM = (
    "No coding agent is available. Set an API key, run inside a host "
    "(Claude Code, Codex, or Antigravity), or start a local model server."
)


def open_sandbox(root: Path, kind: str) -> Sandbox:
    verify = _module("vibeguard.verify")
    if verify is not None and hasattr(verify, "make_sandbox"):
        return verify.make_sandbox(root, kind=kind)
    from vibeguard.run.sandbox import make_sandbox

    return make_sandbox(root, kind=kind)


def execute_gates(ctx: FixContext, cwd: Path, gates=None) -> CheckResult:
    verify = _module("vibeguard.verify")
    if verify is not None and hasattr(verify, "run_gates"):
        return verify.run_gates(ctx, cwd, gates=gates)
    from vibeguard.run.sandbox import run_gates

    return run_gates(ctx, cwd, gates=gates)


def take_snapshot(tree: Path):
    verify = _module("vibeguard.verify")
    if verify is not None and hasattr(verify, "snapshot"):
        return verify.snapshot(tree)
    from vibeguard.run.sandbox import snapshot

    return snapshot(tree)


def guard_tamper(before, tree: Path, allowed: frozenset[str] = frozenset()) -> CheckResult:
    verify = _module("vibeguard.verify")
    if verify is not None and hasattr(verify, "check_tamper"):
        return verify.check_tamper(before, tree, allowed_signatures=allowed)
    from vibeguard.run.sandbox import check_tamper

    return check_tamper(before, tree, allowed_signatures=allowed)


def run_property(ctx: FixContext, cwd: Path, changed: Mapping[str, frozenset[int]]) -> CheckResult:
    return _probe("property_check", "properties", ctx, cwd, changed)


def run_mutation(ctx: FixContext, cwd: Path, changed: Mapping[str, frozenset[int]]) -> CheckResult:
    return _probe("mutation_check", "mutation", ctx, cwd, changed)


def run_differential(ctx: FixContext, cwd: Path, changed: Mapping[str, frozenset[int]]) -> CheckResult:
    return _probe("differential_check", "differential", ctx, cwd, changed)


def run_runtime(ctx: FixContext, cwd: Path) -> CheckResult:
    runtime = _module("vibeguard.runtime")
    if runtime is None or not hasattr(runtime, "runtime_check"):
        return CheckResult("runtime", Verdict.PASS)
    return runtime.runtime_check(ctx, cwd)


def probes_available() -> bool:
    module = _module("vibeguard.probes")
    if module is None:
        return False
    return all(hasattr(module, name) for name in ("property_check", "mutation_check", "differential_check"))


def runtime_available() -> bool:
    module = _module("vibeguard.runtime")
    return module is not None and hasattr(module, "runtime_check")


def resolve_team(root: Path, local: bool | None, team: Team | None) -> Team:
    if team is not None:
        return team
    agents = _module("vibeguard.agents")
    if agents is None or not hasattr(agents, "select_team"):
        return Team(host=None, providers=())
    return agents.select_team(root, local=local)


def team_text(team: Team) -> str:
    agents = _module("vibeguard.agents")
    if agents is not None and hasattr(agents, "describe_team"):
        return agents.describe_team(team)
    if team.can_fix:
        return team.host.name if team.host is not None else "model providers"
    return MISSING_TEAM


def _probe(
    function: str,
    node: str,
    ctx: FixContext,
    cwd: Path,
    changed: Mapping[str, frozenset[int]],
) -> CheckResult:
    probes = _module("vibeguard.probes")
    if probes is None or not hasattr(probes, function):
        return CheckResult(node, Verdict.PASS)
    return getattr(probes, function)(ctx, cwd, changed)


def _module(name: str):
    try:
        return importlib.import_module(name)
    except ImportError:
        return None
