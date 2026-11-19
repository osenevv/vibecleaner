"""Send one prompt to a judge, or to the host in a fresh directory."""

from __future__ import annotations

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


class HostJudge:
    """Runs the host in an empty directory so the generator's files stay untouched."""

    def __init__(self, host: AgentHost) -> None:
        self.name = host.name
        self.family = host.family
        self.local = False
        self.capabilities = Capabilities(context_tokens=16_000)
        self._host = host

    def complete(self, system: str, prompt: str, *, json_mode: bool = False) -> str:
        scratch = Path(tempfile.mkdtemp(prefix="vibecleaner-judge-"))
        instructions = (
            f"{system}\n\n{prompt}\n\n"
            "Write only the JSON answer to answer.json in this directory."
        )
        try:
            result = self._host.run_task(scratch, instructions, timeout_s=120)
            answer = scratch / "answer.json"
            if answer.is_file():
                return answer.read_text(encoding="utf-8")
            if result.stdout.strip():
                return result.stdout
            return ""
        finally:
            shutil.rmtree(scratch, ignore_errors=True)

    def yes_probability(self, system: str, prompt: str) -> float | None:
        return None


def iter_judges(team: Team) -> tuple[Provider | HostJudge, ...]:
    found = team.for_role(Role.JUDGE)
    if found:
        return found
    if team.host is not None:
        return (HostJudge(team.host),)
    return ()


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
