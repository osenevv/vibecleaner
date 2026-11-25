"""Send one prompt to a judge, or to the host in a fresh directory."""

from __future__ import annotations

import asyncio
import logging
import shutil
import tempfile
from pathlib import Path

from vibecleaner.fix_contract import (
    AgentHost,
    Capabilities,
    Provider,
    ProviderError,
    Role,
    Team,
)

log = logging.getLogger("vibecleaner.jury")
DEFAULT_JUDGE_TIMEOUT_S = 120.0


class HostJudge:
    """Runs the host in an empty directory so the generator's files stay untouched."""

    def __init__(self, host: AgentHost) -> None:
        self.name = host.name
        self.family = host.family
        self.local = False
        self.capabilities = Capabilities(context_tokens=16_000)
        self._host = host

    def complete(
        self,
        system: str,
        prompt: str,
        *,
        json_mode: bool = False,
        timeout_s: float = DEFAULT_JUDGE_TIMEOUT_S,
    ) -> str:
        del json_mode
        scratch = Path(tempfile.mkdtemp(prefix="vibecleaner-judge-"))
        try:
            return self._run_in_scratch(scratch, system, prompt, timeout_s=timeout_s)
        finally:
            shutil.rmtree(scratch, ignore_errors=True)

    async def complete_async(
        self,
        system: str,
        prompt: str,
        *,
        json_mode: bool = False,
        timeout_s: float = DEFAULT_JUDGE_TIMEOUT_S,
    ) -> str:
        del json_mode
        scratch = Path(tempfile.mkdtemp(prefix="vibecleaner-judge-"))
        try:
            return await asyncio.wait_for(
                asyncio.to_thread(self._run_in_scratch, scratch, system, prompt, timeout_s),
                timeout=timeout_s,
            )
        except TimeoutError as exc:
            raise ProviderError(f"host judge {self.name} timed out after {timeout_s:.1f}s") from exc
        finally:
            shutil.rmtree(scratch, ignore_errors=True)

    def _run_in_scratch(self, scratch: Path, system: str, prompt: str, timeout_s: float) -> str:
        instructions = (
            f"{system}\n\n{prompt}\n\n"
            "Write only the JSON answer to answer.json in this directory."
        )
        result = self._host.run_task(scratch, instructions, timeout_s=timeout_s)
        answer = scratch / "answer.json"
        if answer.is_file():
            return answer.read_text(encoding="utf-8")
        if result.stdout.strip():
            return result.stdout
        return ""

    def yes_probability(self, system: str, prompt: str) -> float | None:
        del system, prompt
        return None


def iter_judges(team: Team) -> tuple[Provider | HostJudge, ...]:
    found = team.for_role(Role.JUDGE)
    if found:
        return found
    if team.host is not None:
        return (HostJudge(team.host),)
    return ()


async def complete_judge_async(
    judge: Provider | HostJudge,
    system: str,
    prompt: str,
    *,
    json_mode: bool = True,
    timeout_s: float = DEFAULT_JUDGE_TIMEOUT_S,
) -> str:
    """Dispatch a single judge call without blocking the event loop."""
    if isinstance(judge, HostJudge):
        return await judge.complete_async(system, prompt, json_mode=json_mode, timeout_s=timeout_s)
    async_fn = getattr(judge, "complete_async", None)
    if callable(async_fn):
        try:
            return await asyncio.wait_for(
                async_fn(system, prompt, json_mode=json_mode),
                timeout=timeout_s,
            )
        except TimeoutError as exc:
            raise ProviderError(f"judge {judge.name} timed out after {timeout_s:.1f}s") from exc
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(judge.complete, system, prompt, json_mode=json_mode),
            timeout=timeout_s,
        )
    except TimeoutError as exc:
        raise ProviderError(f"judge {judge.name} timed out after {timeout_s:.1f}s") from exc


def complete_first(providers: tuple[Provider | HostJudge, ...], system: str, prompt: str) -> str:
    if not providers:
        raise ProviderError("no model is available")
    errors: list[str] = []
    for provider in providers:
        try:
            return provider.complete(system, prompt, json_mode=True)
        except ProviderError as exc:
            log.warning("model %s failed: %s", provider.name, exc)
            errors.append(f"{provider.name}: {exc}")
    raise ProviderError("; ".join(errors))


async def complete_first_async(
    providers: tuple[Provider | HostJudge, ...],
    system: str,
    prompt: str,
    *,
    timeout_s: float = DEFAULT_JUDGE_TIMEOUT_S,
) -> str:
    if not providers:
        raise ProviderError("no model is available")
    errors: list[str] = []
    for provider in providers:
        try:
            return await complete_judge_async(provider, system, prompt, json_mode=True, timeout_s=timeout_s)
        except ProviderError as exc:
            log.warning("model %s failed: %s", provider.name, exc)
            errors.append(f"{provider.name}: {exc}")
    raise ProviderError("; ".join(errors))
