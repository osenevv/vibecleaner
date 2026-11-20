"""Draft unified diffs for critical findings with a generative model."""

from __future__ import annotations

import asyncio
import logging
import os
import re
from typing import Any

from vibeguard.models import FIX_THRESHOLD, Finding, ScanContext, Severity

log = logging.getLogger(__name__)

DEFAULT_FIX_MODEL = "gemini-2.5-flash"
_DIFF_FENCE = re.compile(r"```(?:diff)?\s*\n(.*?)```", re.DOTALL | re.IGNORECASE)


def generate_fixes(
    findings: list[Finding],
    ctx: ScanContext,
    model: str | None = None,
    *,
    client: Any = None,
) -> int:
    """Draft patches for critical findings. Returns how many diffs were kept.

    Layer 1 candidates are severity ``critical``. Layer 2 candidates are
    severity ``critical`` and probability >= ``FIX_THRESHOLD``. Without an API
    key (and without an injected client) this logs a warning and returns 0.
    """
    if client is None and _api_key() is None:
        log.warning("Skipping --fix: set GEMINI_API_KEY or GOOGLE_API_KEY to draft patches.")
        return 0
    candidates = [finding for finding in findings if _eligible(finding)]
    if not candidates:
        return 0
    model_name = model or os.environ.get("VIBEGUARD_FIX_MODEL") or DEFAULT_FIX_MODEL
    return asyncio.run(_draft_all(candidates, ctx, model_name, client))


def _eligible(finding: Finding) -> bool:
    if finding.severity != Severity.CRITICAL:
        return False
    if finding.layer == 1:
        return True
    return finding.probability is not None and finding.probability >= FIX_THRESHOLD


def _api_key() -> str | None:
    for name in ("GEMINI_API_KEY", "GOOGLE_API_KEY"):
        value = os.environ.get(name, "").strip()
        if value:
            return value
    return None


async def _draft_all(
    findings: list[Finding],
    ctx: ScanContext,
    model_name: str,
    client: Any,
) -> int:
    if client is None:
        from google import genai

        client = genai.Client(api_key=_api_key())
    semaphore = asyncio.Semaphore(4)

    async def draft(finding: Finding) -> int:
        async with semaphore:
            try:
                response = await client.aio.models.generate_content(
                    model=model_name,
                    contents=_prompt(finding, ctx),
                )
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                log.warning(
                    "Fix generation failed for %s %s:%s: %s",
                    finding.rule_id,
                    finding.file,
                    finding.line,
                    exc,
                )
                return 0
            diff = _extract_diff(_response_text(response))
            if diff is None:
                log.warning(
                    "Fix for %s %s:%s was not a unified diff",
                    finding.rule_id,
                    finding.file,
                    finding.line,
                )
                return 0
            finding.fix_patch = diff
            return 1

    drafted = await asyncio.gather(*(draft(finding) for finding in findings))
    return sum(drafted)


def _prompt(finding: Finding, ctx: ScanContext) -> str:
    spec = finding.spec
    return (
        "Write a unified diff that fixes the issue below. "
        "Output ONLY the diff. Do not explain. "
        "The diff must contain '---', '+++', and at least one '@@' hunk, "
        "against the given file path. Ignore the line-number prefixes in the excerpt.\n\n"
        f"File: {finding.file}\n"
        f"Rule: {spec.rule_id} {spec.title}\n"
        f"Remediation: {spec.remediation}\n"
        f"Finding: {finding.message}\n\n"
        "Excerpt:\n"
        f"{_excerpt(finding, ctx)}\n"
    )


def _excerpt(finding: Finding, ctx: ScanContext) -> str:
    fallback: str | None = None
    for unit in ctx.units:
        if unit.file != finding.file or not unit.contains_line(finding.line):
            continue
        numbered = _number_lines(unit.source, unit.start_line)
        if finding.symbol and unit.name == finding.symbol:
            return numbered
        fallback = numbered
    if fallback is not None:
        return fallback
    for source in ctx.files:
        if source.path != finding.file:
            continue
        rows = source.text.splitlines()
        if not rows:
            break
        start = max(1, finding.line - 5)
        end = min(len(rows), (finding.end_line or finding.line) + 5)
        return _number_lines("\n".join(rows[start - 1 : end]), start)
    return finding.snippet or ""


def _number_lines(source: str, start: int, limit: int = 200) -> str:
    return "\n".join(
        f"{start + offset}: {text}" for offset, text in enumerate(source.splitlines()[:limit])
    )


def _response_text(response: Any) -> str:
    if response is None:
        return ""
    if isinstance(response, str):
        return response
    if isinstance(response, dict):
        text = response.get("text")
        if isinstance(text, str):
            return text
        return _candidates_text(response.get("candidates"))
    text = getattr(response, "text", None)
    if isinstance(text, str) and text.strip():
        return text
    return _candidates_text(getattr(response, "candidates", None))


def _candidates_text(candidates: Any) -> str:
    if not candidates:
        return ""
    first = candidates[0]
    content = first.get("content") if isinstance(first, dict) else getattr(first, "content", None)
    if isinstance(content, dict):
        parts = content.get("parts")
    elif content is not None:
        parts = getattr(content, "parts", None)
    else:
        parts = None
    if not parts:
        return ""
    chunks: list[str] = []
    for part in parts:
        text = part.get("text") if isinstance(part, dict) else getattr(part, "text", None)
        if isinstance(text, str):
            chunks.append(text)
    return "".join(chunks)


def _extract_diff(text: str) -> str | None:
    if not text or not text.strip():
        return None
    fenced = _DIFF_FENCE.search(text)
    body = fenced.group(1) if fenced else text
    start = body.find("---")
    if start > 0:
        body = body[start:]
    if not _looks_like_diff(body):
        return None
    return body.strip() + "\n"


def _looks_like_diff(text: str) -> bool:
    return "---" in text and "+++" in text and "@@" in text
