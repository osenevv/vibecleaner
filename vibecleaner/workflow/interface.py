"""Apply the workflow skills, in order, when the tree has a page."""

from __future__ import annotations

import tempfile
from pathlib import Path, PurePosixPath

from vibecleaner.fix_contract import FixContext, RunOutcome, RunResult
from vibecleaner.verify.files import iter_files
from vibecleaner.workflow.documents import SKILL_ORDER, SKILLS, THIRD_PARTY

INTERFACE_SKILLS = SKILL_ORDER
_PAGE_SUFFIXES = frozenset({".htm", ".html", ".jsx", ".svelte", ".tsx", ".vue"})
_SKILL_TIMEOUT_S = 180
MANDATORY_AGENT_RULES = (
    "Comments should explain constraints or non-obvious decisions. "
    "Keep task history and conversations out of code and user documentation.",
    "Keep documentation concise and factual. Do not use punchy slogans or promotional language.",
    "Update documentation where users need it to understand changed usage. "
    "Small features do not automatically need a README headline, new section, or feature announcement. "
    "Prefer a short update in the existing relevant section.",
    "Do not commit superfluous documentation or scatter unnecessary Markdown files through the repository. "
    "New documents need a clear purpose beyond recording the current task. "
    "Link to authoritative code and configuration instead of duplicating details.",
    "Do not commit build outputs (`dist/`), extension `.zip` archives, model weights, or profiling dumps. "
    "Intentional tracked assets are limited to extension icons, static web assets, and explicitly requested docs media.",
    "Run every test, build, or measurement needed to validate the change instead of skipping it and adding a caveat that it was not run. "
    "Only report a browser, GPU, or environment gap when the required runtime or hardware is genuinely unavailable. "
    "Report the checks actually run and their results, and do not present inferred correctness or speedups as measured.",
    "Do not write the PR description yourself. Ask the user to write it out after giving them sufficient information about the changes. "
    "If the user still asks you to write the description yourself, give them a warning but proceed with noting this override in the PR description.",
    "Do not reply to the reviewer's comment yourself. Same rule as above.",
)


def apply_interface(ctx: FixContext) -> tuple[RunResult | None, bool]:
    """Give the host one instruction that contains every interface skill.

    Returns ``(None, False)`` when the tree has no page, ``(None, True)`` when
    the instruction finished, and a ``RunResult`` when it did not run.
    """
    pages = page_paths(ctx.root)
    if not pages:
        return None, False
    if ctx.team.host is None:
        names = ", ".join(INTERFACE_SKILLS)
        return (
            RunResult(
                RunOutcome.NEEDS_YOU,
                "The interface instruction has not run.",
                questions=(f"Set VIBECLEANER_HOST so this run can apply {names}.",),
            ),
            False,
        )
    path = _write_instruction(interface_instruction(", ".join(pages)))
    ctx.progress("Applying the interface instruction")
    result = ctx.team.host.run_task(ctx.root, _task(path), timeout_s=_SKILL_TIMEOUT_S)
    if result.ok:
        return None, True
    reason = "timed out" if result.timed_out else f"exited {result.returncode}"
    return (
        RunResult(
            RunOutcome.NEEDS_YOU,
            f"The interface instruction did not finish ({reason}).",
            questions=(f"Follow {path}",),
        ),
        False,
    )


def page_paths(root: Path) -> tuple[str, ...]:
    """Repo-relative pages. HTML, JSX, TSX, Vue, and Svelte count. Plain scripts do not."""
    found: list[str] = []
    for rel, _path in iter_files(root):
        if PurePosixPath(rel).suffix.lower() in _PAGE_SUFFIXES:
            found.append(rel)
    return tuple(found)


def interface_instruction(pages: str) -> str:
    """The workflow skills, in order, as one task."""
    chunks = [
        "These rules are mandatory. A run that breaks one is not done.",
        *[f"- {rule}" for rule in MANDATORY_AGENT_RULES],
        "",
        "Apply these skills in the order written. Each skill owns its rules.",
        "Do not do a later skill's work early, and do not redo an earlier skill's work.",
        f"The pages are {pages}.",
        "There is no skill folder to open.",
        "Do not run vibecleaner.",
        "",
    ]
    for name in INTERFACE_SKILLS:
        chunks.append(f"----- {name} -----")
        chunks.append(SKILLS[name].strip())
        chunks.append("")
    chunks.append("----- third-party notices -----")
    chunks.append("")
    for rel, body in THIRD_PARTY.items():
        chunks.append(f"----- {rel} -----")
        chunks.append(body.strip())
        chunks.append("")
    return "\n".join(chunks).rstrip() + "\n"


def interface_task(pages: tuple[str, ...]) -> tuple[Path, str]:
    """Write the interface instruction to a file once and return ``(path, short_prompt)``."""
    path = _write_instruction(interface_instruction(", ".join(pages)))
    return path, _task(path)


def _write_instruction(text: str) -> Path:
    handle = tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        prefix="vibecleaner-interface-",
        suffix=".md",
        delete=False,
    )
    with handle:
        handle.write(text)
    return Path(handle.name)


def _task(path: Path) -> str:
    return (
        f"Follow the instruction at {path}. "
        "That file is the whole task: the mandatory agent rules, then the workflow skills in order. "
        "Do not write the PR description yourself. "
        "Do not reply to the reviewer's comment yourself. "
        "Do not run vibecleaner."
    )
