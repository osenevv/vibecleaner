"""Plain-English risk explanations, copy-paste AI Fix Prompts, clipboard copy, and --autofix runner."""

from __future__ import annotations

import shlex
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from vibecleaner.agents.hosts import execute_argv, preset_argv
from vibecleaner.fix_contract import ProviderError
from vibecleaner.models import Finding, ScanResult, Severity
from vibecleaner.redact import redact_secrets

_SEVERITY_RANK = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
}

_PLAIN_EXPLANATIONS: dict[str, tuple[str, str]] = {
    "D1.env_file_committed": (
        "A real .env secrets file is in your repo and will leak credentials if pushed.",
        "Remove the .env file from git tracking, add `.env*` to `.gitignore`, and rotate every key inside it.",
    ),
    "D1.next_public_secret": (
        "A private secret is exposed to every visitor's browser via NEXT_PUBLIC_*.",
        "Move this key to a server-only environment variable (remove the NEXT_PUBLIC_ prefix) and rotate the key.",
    ),
    "D1.hardcoded_secret": (
        "A secret key or credential is hardcoded in source code.",
        "Read the credential from an environment variable (e.g. `os.environ` / `process.env`) and rotate the exposed value.",
    ),
    "D1.high_entropy_literal": (
        "A high-entropy token is hardcoded next to a secret-like variable name.",
        "Replace the literal with an environment variable lookup and rotate the token if it is real.",
    ),
    "D2.missing_rls": (
        "Anyone with your public Supabase anon key can read or modify every row in this table.",
        "Add `ALTER TABLE <table> ENABLE ROW LEVEL SECURITY;` and explicit `CREATE POLICY` rules scoping access to `auth.uid()`.",
    ),
    "D2.rls_no_policy": (
        "Row Level Security is enabled on this table without any policies.",
        "Add explicit `CREATE POLICY` statements defining which authenticated users can SELECT, INSERT, UPDATE, or DELETE.",
    ),
    "D2.cors_wildcard_credentials": (
        "Any malicious website can make authenticated requests to your API using a visitor's cookies.",
        "Replace wildcard `*` CORS origins with an explicit allowlist of your own frontend domains.",
    ),
    "D3.missing_auth": (
        "Any unauthenticated stranger on the internet can call this endpoint or paid action.",
        "Require authentication (session/JWT check or auth middleware) at the top of the handler before reading or writing data.",
    ),
    "D4.idor_or_price_trust": (
        "A user can tamper with the request (e.g. change price, role, or another user's ID) in DevTools.",
        "Derive user/org identity from the verified server session and look up prices/roles from your database on the server.",
    ),
    "D5.prompt_injection": (
        "Untrusted user input reaches LLM system instructions or a dangerous tool (shell/SQL/file/webhook).",
        "Keep user text out of system instructions (use the user role) and validate/allowlist all tool arguments before execution.",
    ),
    "D6a.silent_exception": (
        "Errors are silently swallowed, hiding real crashes and security failures.",
        "Catch only the specific expected exception and log, translate, or re-raise it.",
    ),
    "D6a.god_module": (
        "One oversized file mixes HTTP handling, database queries, and business logic.",
        "Split this file by feature into focused modules with a single responsibility each.",
    ),
    "D6a.deprecated_sdk": (
        "This code calls a deprecated SDK API that breaks on current package versions.",
        "Migrate to the current supported SDK call signature.",
    ),
    "D6a.passthrough_wrapper": (
        "A wrapper function only forwards `*args, **kwargs` without adding behavior.",
        "Remove the wrapper and call the underlying function directly.",
    ),
    "D6b.hardcoded_mock_stub": (
        "A production code path returns hardcoded dummy data or a TODO stub.",
        "Implement the real production logic or fail explicitly instead of returning fake success data.",
    ),
    "D7a.n_plus_one_or_unbounded": (
        "A loop runs a database/HTTP query per item or fetches an entire table with no LIMIT.",
        "Batch the query outside the loop and add pagination (`LIMIT`/`OFFSET` or cursor).",
    ),
    "D7b.missing_boundary_schema": (
        "Raw unvalidated request JSON is trusted directly in the handler.",
        "Validate the request body at the boundary with a Pydantic model or Zod schema before using it.",
    ),
}

_AGENT_PRESETS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("claude", ("claude", "-p")),
    ("codex", ("codex", "exec")),
    ("gemini", ("gemini", "-p")),
    ("agy", ("agy", "-p")),
)

_CLIPBOARD_COMMANDS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("pbcopy", ("pbcopy",)),
    ("wl-copy", ("wl-copy",)),
    ("xclip", ("xclip", "-selection", "clipboard")),
    ("xsel", ("xsel", "--clipboard", "--input")),
    ("clip", ("clip",)),
)


@dataclass(frozen=True)
class AutofixOutcome:
    status: str  # ran | copied | no_agent | failed
    detail: str
    agent_name: str | None = None
    returncode: int | None = None


def plain_explanation(finding: Finding) -> tuple[str, str]:
    """Return ``(plain_risk, concrete_fix)`` for a finding."""
    if finding.rule_id in _PLAIN_EXPLANATIONS:
        return _PLAIN_EXPLANATIONS[finding.rule_id]
    spec = finding.spec
    risk = redact_secrets(finding.message) if finding.message else spec.title
    fix = spec.remediation or "Fix the issue at the reported location."
    return risk, fix


def actionable_findings(findings: list[Finding], fail_on: str = "high") -> list[Finding]:
    """Return findings at or above ``fail_on`` (or all findings when ``fail_on == 'none'``)."""
    if not findings:
        return []
    if fail_on == "none":
        return list(findings)
    cutoff = _SEVERITY_RANK[Severity(fail_on)]
    selected = [finding for finding in findings if _SEVERITY_RANK[finding.severity] >= cutoff]
    return selected if selected else list(findings)


def build_fix_prompt(result: ScanResult, *, fail_on: str = "high") -> str:
    """Build a self-contained prompt an AI coding agent can execute to fix the findings."""
    items = actionable_findings(result.findings, fail_on=fail_on)
    if not items:
        return ""
    noun = "blocker" if len(items) == 1 else "blockers"
    lines = [
        f"Fix these {len(items)} VibeCleaner {noun} in this repository:",
        "",
    ]
    for index, finding in enumerate(items, start=1):
        risk, fix = plain_explanation(finding)
        detail = redact_secrets(finding.message)
        lines.append(
            f"{index}. {finding.file}:{finding.line} [{finding.severity.value.upper()} {finding.rule_id}]: {risk}"
        )
        if detail and detail != risk:
            lines.append(f"   Finding: {detail}")
        lines.append(f"   Fix: {fix}")
    lines.extend(
        [
            "",
            "Rules:",
            "- Fix the root cause in application code. Do not disable VibeCleaner checks, lower thresholds, or suppress findings.",
            "- Use real implementations in tests instead of test doubles; add or update a regression test for each behavior fix.",
            "- When finished, run `vibecleaner` and confirm it passes with exit code 0.",
        ]
    )
    return "\n".join(lines)


_ALLOWED_CLIPBOARD_CMDS = frozenset(cmd for _name, cmd in _CLIPBOARD_COMMANDS)
_ALLOWED_AGENT_BINS = frozenset(cmd[0] for _name, cmd in _AGENT_PRESETS)


def copy_to_clipboard(content: str) -> tuple[bool, str]:
    """Copy ``content`` to the OS clipboard using the first available clipboard tool."""
    allowed_cmds = _ALLOWED_CLIPBOARD_CMDS
    for name, cmd in _CLIPBOARD_COMMANDS:
        if cmd not in allowed_cmds or shutil.which(cmd[0]) is None:
            continue
        proc = subprocess.run(cmd, input=content, text=True, capture_output=True, check=False)
        if proc.returncode == 0:
            return True, name
    return False, "no clipboard utility (pbcopy, wl-copy, xclip, xsel, clip) found on PATH"


def resolve_agent_command(agent: str | None = None) -> tuple[str, list[str]] | None:
    """Resolve an AI coding agent CLI command from ``--agent`` or ``PATH``."""
    preset_map = dict(_AGENT_PRESETS)
    if agent:
        cleaned = agent.strip()
        if cleaned in preset_map:
            cmd = list(preset_map[cleaned])
            return (cleaned, cmd) if shutil.which(cmd[0]) else None
        parts = shlex.split(cleaned)
        if not parts:
            return None
        exe = parts[0]
        if shutil.which(exe) or Path(exe).expanduser().is_file():
            return exe, parts
        return None
    for name, cmd in _AGENT_PRESETS:
        if shutil.which(cmd[0]):
            return name, list(cmd)
    return None


def _bare_preset(name: str, base_cmd: list[str]) -> bool:
    for preset_name, prefix in _AGENT_PRESETS:
        if name == preset_name and base_cmd == list(prefix):
            return True
    return False


def run_agent_fix(root: Path, instructions: str, *, agent: str | None = None) -> AutofixOutcome:
    """Invoke a headless AI coding agent with ``instructions``, or fall back to clipboard copy."""
    resolved = resolve_agent_command(agent)
    if resolved is None:
        if agent is not None:
            return AutofixOutcome(
                status="failed",
                agent_name=agent,
                returncode=2,
                detail=f"agent command not found: {agent}",
            )
        copied, info = copy_to_clipboard(instructions)
        if copied:
            return AutofixOutcome(
                status="copied",
                detail=(
                    f"No headless agent CLI (claude, codex, gemini, agy) found on PATH. "
                    f"Copied the fix prompt to your clipboard via {info}. Paste (Cmd+V / Ctrl+V) into your AI editor."
                ),
            )
        return AutofixOutcome(
            status="no_agent",
            detail=(
                "No headless agent CLI (claude, codex, gemini, agy) found on PATH and clipboard copy was unavailable. "
                "Copy the fix prompt printed above into your AI editor."
            ),
        )

    name, base_cmd = resolved
    if _bare_preset(name, base_cmd):
        argv = preset_argv(name, instructions)
    elif any("{prompt}" in part for part in base_cmd):
        argv = [part.replace("{prompt}", instructions) for part in base_cmd]
    else:
        argv = [*base_cmd, instructions]

    allowed_bins = _ALLOWED_AGENT_BINS | ({argv[0]} if agent is not None else set())
    if argv[0] not in allowed_bins:
        return AutofixOutcome(
            status="failed",
            agent_name=name,
            returncode=2,
            detail=f"refused to run unallowlisted agent binary: {argv[0]}",
        )

    try:
        result = execute_argv(argv, cwd=root, timeout_s=None, capture=False)
    except ProviderError as exc:
        return AutofixOutcome(status="failed", agent_name=name, returncode=2, detail=str(exc))
    if not result.ok:
        return AutofixOutcome(
            status="failed",
            agent_name=name,
            returncode=result.returncode,
            detail=f"agent `{name}` exited with code {result.returncode}",
        )
    return AutofixOutcome(
        status="ran",
        agent_name=name,
        returncode=0,
        detail=f"agent `{name}` completed; re-scanning repository...",
    )
