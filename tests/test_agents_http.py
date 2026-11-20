"""Local model detection and OpenAI-compatible provider calls."""

from __future__ import annotations

import math
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from agent_http import Bench, base_url, serve  # noqa: E402

from vibeguard.agents.local import _DEFAULT_TARGETS, _probe_targets
from vibeguard.agents.providers import (
    AnthropicProvider,
    OpenAICompatibleProvider,
    yes_probability_from,
)
from vibeguard.agents.team import describe_team, select_team
from vibeguard.fix_contract import Capabilities, ProviderError, Role
from vibeguard.models import DEFAULT_THRESHOLD


def test_probe_order_follows_the_given_targets() -> None:
    assert [port for port, _kind in _DEFAULT_TARGETS] == [11434, 1234, 8080, 8000]
    alpha = Bench([{"id": "alpha"}])
    beta = Bench([{"id": "beta"}])
    with serve(alpha) as first, serve(beta) as second:
        found = _probe_targets(
            [(second.server_address[1], "second"), (first.server_address[1], "first")],
            2,
        )
    assert [(item.kind, item.models) for item in found] == [
        ("second", ("beta",)),
        ("first", ("alpha",)),
    ]


def test_explicit_url_wins_and_embedding_models_are_dropped(tmp_path: Path) -> None:
    bench = Bench(
        [
            {"id": "qwen2.5-coder"},
            {"id": "long-context", "max_model_len": 32768},
            {"id": "nomic-embed-text"},
        ]
    )
    with serve(bench) as httpd:
        url = base_url(httpd)
        team = select_team(
            tmp_path,
            env={"VIBEGUARD_LOCAL_URL": url, "OPENAI_API_KEY": "sk-test"},
        )
        local_only = select_team(tmp_path, local=True, env={"VIBEGUARD_LOCAL_URL": url})
    names = [provider.model for provider in team.providers if provider.local]
    assert names == ["qwen2.5-coder", "long-context"]
    judges = team.for_role(Role.JUDGE)
    assert judges[0].local
    assert judges[0].family == "local:qwen"
    assert any(provider.family == "openai" for provider in judges)
    patchers = team.for_role(Role.PATCHER)
    assert [provider.model for provider in patchers if provider.local] == ["long-context"]
    assert all(provider.family == "openai" for provider in team.for_role(Role.BROWSER))
    assert describe_team(local_only) == "Local models"


def test_ollama_show_supplies_tools_vision_and_context(tmp_path: Path) -> None:
    bench = Bench(
        [{"id": "qwen2.5-coder"}],
        show={
            "capabilities": ["completion", "tools", "vision"],
            "model_info": {"qwen2.context_length": 32768},
        },
    )
    with serve(bench) as httpd:
        url = base_url(httpd)
        team = select_team(tmp_path, local=True, env={"VIBEGUARD_LOCAL_URL": url})
    browser = team.for_role(Role.BROWSER)
    assert len(browser) == 1
    assert browser[0].capabilities == Capabilities(32768, tool_calls=True, vision=True)
    assert describe_team(team) == "A local model"


def test_config_is_lower_priority_than_env(tmp_path: Path) -> None:
    with serve(Bench([{"id": "from-config"}])) as config_server, serve(Bench([{"id": "from-env"}])) as env_server:
        config_url = base_url(config_server)
        env_url = base_url(env_server)
        path = tmp_path / ".vibeguard" / "config.json"
        path.parent.mkdir()
        path.write_text(
            '{"other": true, "local": {"url": "%s", "model": "from-config"}}\n' % config_url,
            encoding="utf-8",
        )
        from_env = select_team(
            tmp_path,
            env={"VIBEGUARD_LOCAL_URL": env_url, "VIBEGUARD_LOCAL_MODEL": "from-env"},
        )
        from_file = select_team(tmp_path, env={})
        skipped = select_team(
            tmp_path,
            local=False,
            env={"OPENAI_API_KEY": "sk-test", "VIBEGUARD_LOCAL_URL": env_url},
        )
    assert [provider.model for provider in from_env.providers] == ["from-env"]
    assert [provider.model for provider in from_file.providers] == ["from-config"]
    assert [provider.family for provider in skipped.providers] == ["openai"]


def test_local_only_fails_closed_without_a_server(tmp_path: Path) -> None:
    with pytest.raises(ProviderError, match="did not respond"):
        select_team(tmp_path, local=True, env={"VIBEGUARD_LOCAL_URL": "http://127.0.0.1:1"})
    with pytest.raises(ProviderError, match="no local model server"):
        select_team(tmp_path, local=True, env={"VIBEGUARD_LOCAL_MODEL": "vibeguard-no-such-model-zz"})
    with pytest.raises(ProviderError, match="loopback"):
        select_team(tmp_path, env={"VIBEGUARD_LOCAL_URL": "http://192.0.2.1/v1"})
    quiet = select_team(tmp_path, local=False, env={"VIBEGUARD_LOCAL_URL": "http://127.0.0.1:1"})
    assert quiet.providers == ()


def test_chat_completion_logprobs_and_errors() -> None:
    bench = Bench([{"id": "qwen2.5-coder"}], mode="logprobs")
    with serve(bench) as httpd:
        url = base_url(httpd)
        provider = OpenAICompatibleProvider(
            name="local:qwen2.5-coder",
            family="local:qwen",
            local=True,
            capabilities=Capabilities(8_000),
            base_url=url,
            model="qwen2.5-coder",
            api_key=None,
            timeout_s=2,
        )
        assert provider.complete("system", "fix it", json_mode=True) == "patched"
        yes = provider.yes_probability("Judge.", "Is this safe?")
        no = provider.yes_probability("Judge.", "UNSAFE input")
    assert yes is not None and yes >= DEFAULT_THRESHOLD
    assert math.isclose(yes, 0.9, rel_tol=1e-6)
    assert no is not None and no < DEFAULT_THRESHOLD
    assert math.isclose(no, 0.2, rel_tol=1e-6)
    assert bench.seen[0]["body"]["response_format"] == {"type": "json_object"}
    assert bench.seen[0]["authorization"] is None

    rejected = Bench([{"id": "qwen2.5-coder"}], mode="reject-logprobs")
    with serve(rejected) as httpd:
        provider = OpenAICompatibleProvider(
            name="local:qwen2.5-coder",
            family="local:qwen",
            local=True,
            capabilities=Capabilities(8_000),
            base_url=base_url(httpd),
            model="qwen2.5-coder",
            api_key="sk-test",
            timeout_s=2,
        )
        assert provider.yes_probability("Judge.", "Is this safe?") is None
        assert rejected.seen[0]["authorization"] == "Bearer sk-test"

    maybe = Bench([{"id": "qwen2.5-coder"}], mode="maybe")
    with serve(maybe) as httpd:
        provider = OpenAICompatibleProvider(
            name="local:qwen2.5-coder",
            family="local:qwen",
            local=True,
            capabilities=Capabilities(8_000),
            base_url=base_url(httpd),
            model="qwen2.5-coder",
            api_key=None,
            timeout_s=2,
        )
        assert provider.yes_probability("Judge.", "Is this safe?") is None

    broken = Bench([{"id": "qwen2.5-coder"}], mode="error")
    with serve(broken) as httpd:
        provider = OpenAICompatibleProvider(
            name="openai:gpt-4o",
            family="openai",
            local=False,
            capabilities=Capabilities(128_000, tool_calls=True, vision=True, logprobs=True),
            base_url=base_url(httpd),
            model="gpt-4o",
            api_key="sk-test",
            timeout_s=2,
        )
        with pytest.raises(ProviderError, match="HTTP 500"):
            provider.complete("system", "fix it")

    offline = OpenAICompatibleProvider(
        name="local:qwen",
        family="local:qwen",
        local=True,
        capabilities=Capabilities(8_000),
        base_url="http://127.0.0.1:1",
        model="qwen",
        api_key=None,
        timeout_s=1,
    )
    with pytest.raises(ProviderError, match="127.0.0.1:1"):
        offline.complete("system", "fix it")
    assert yes_probability_from([("maybe", -0.1)]) is None


def test_anthropic_complete_and_yes_probability_without_logprobs() -> None:
    bench = Bench([{"id": "unused"}])
    with serve(bench) as httpd:
        provider = AnthropicProvider("test-key", "claude-sonnet-4-6", base_url(httpd), timeout_s=2)
        assert provider.yes_probability("system", "Is it safe?") is None
        assert bench.seen == []
        text = provider.complete("system", "fix it", json_mode=True)
    assert text == "anthropic:fix it"
    assert bench.seen[0]["path"] == "/v1/messages"
    assert "JSON" in bench.seen[0]["body"]["system"]
    with pytest.raises(ProviderError, match="127.0.0.1:1"):
        AnthropicProvider("test-key", "claude-sonnet-4-6", "http://127.0.0.1:1", timeout_s=1).complete("s", "p")
