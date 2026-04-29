"""Triage routing tests.

The triage step previously POSTed raw OpenAI ``/v1/chat/completions`` regardless
of YAML config — Anthropic-keyed runs got 401 silently and returned 0 dismissals.
The next iteration tried ``litellm.completion`` directly but that broke in
CI because crewai 1.10+ no longer ships LiteLLM as a transitive dep
(``ModuleNotFoundError: No module named 'litellm'``).

The current implementation reuses ``crewai.LLM`` (already installed and used
by the agent path) so the YAML model prefix and base_url govern the
destination identically to :func:`appsec_crew.utils.llm.build_llm`.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from appsec_crew.settings import LlmAgentConfig
from appsec_crew.triage_llm import llm_triage_batch


def _make_llm_class(content_to_return: str):
    """Return a class that mimics ``crewai.LLM``: constructible with kwargs,
    has a ``.call(messages=...)`` method that returns a string."""
    captured: dict = {}

    class _FakeLLM:
        def __init__(self, **kwargs) -> None:
            captured["init"] = kwargs

        def call(self, messages, **_kw):
            captured["messages"] = messages
            return content_to_return

    return _FakeLLM, captured


def test_triage_routes_claude_via_anthropic_prefix() -> None:
    """A bare ``claude-*`` model in YAML must reach crewai.LLM as
    ``anthropic/claude-*`` so the native dispatcher picks the Anthropic
    provider (without the prefix it falls through to OpenAI and 401s)."""
    cfg = LlmAgentConfig(model="claude-sonnet-4-6", api_key="sk-ant-xxx", temperature=0)
    fake_cls, captured = _make_llm_class('{"dismiss": []}')

    with patch("appsec_crew.triage_llm._CrewAILLM", fake_cls):
        out = llm_triage_batch(cfg, agent_role="x", items=[{"index": 0}], guidance="g")

    assert out == []
    init = captured["init"]
    assert init["model"] == "anthropic/claude-sonnet-4-6"
    assert init["api_key"] == "sk-ant-xxx"
    assert "base_url" not in init


def test_triage_routes_gpt_models_to_openai_default() -> None:
    cfg = LlmAgentConfig(model="gpt-4o-mini", api_key="sk-openai", temperature=0)
    fake_cls, captured = _make_llm_class('{"dismiss": []}')

    with patch("appsec_crew.triage_llm._CrewAILLM", fake_cls):
        llm_triage_batch(cfg, agent_role="x", items=[{"index": 0}], guidance="g")

    assert captured["init"]["model"] == "gpt-4o-mini"


def test_triage_honors_base_url_for_compatible_endpoints() -> None:
    cfg = LlmAgentConfig(
        model="gpt-4o-mini",
        api_key="ghp_xxx",
        base_url="https://models.github.ai/inference",
        temperature=0,
    )
    fake_cls, captured = _make_llm_class('{"dismiss": []}')

    with patch("appsec_crew.triage_llm._CrewAILLM", fake_cls):
        llm_triage_batch(cfg, agent_role="x", items=[{"index": 0}], guidance="g")

    init = captured["init"]
    assert init["model"] == "gpt-4o-mini"
    assert init["base_url"] == "https://models.github.ai/inference"


def test_triage_returns_empty_when_call_raises() -> None:
    """Fail-open: any LLM error keeps every finding."""
    cfg = LlmAgentConfig(model="claude-haiku-4-5", api_key="x", temperature=0)

    class _BoomLLM:
        def __init__(self, **_kw) -> None:
            pass

        def call(self, messages, **_kw):
            raise RuntimeError("network")

    with patch("appsec_crew.triage_llm._CrewAILLM", _BoomLLM):
        out = llm_triage_batch(cfg, agent_role="x", items=[{"index": 0}], guidance="g")
    assert out == []


def test_triage_parses_dismiss_array_with_reasons() -> None:
    cfg = LlmAgentConfig(model="claude-haiku-4-5", api_key="x", temperature=0)
    body = json.dumps(
        {
            "dismiss": [
                {"index": 0, "reason": "MD5 used for ETag, not security"},
                {"index": 2, "reason": "test fixture path"},
                {"reason": "missing index — should be skipped"},
                {"index": "bad", "reason": "non-int index — skipped"},
            ]
        }
    )
    fake_cls, _ = _make_llm_class(body)
    with patch("appsec_crew.triage_llm._CrewAILLM", fake_cls):
        out = llm_triage_batch(
            cfg, agent_role="x", items=[{"index": i} for i in range(5)], guidance="g"
        )

    assert {row["index"] for row in out} == {0, 2}
    assert all("reason" in row for row in out)
    assert out[0]["reason"].startswith("MD5 used for ETag")


def test_triage_empty_items_short_circuits() -> None:
    cfg = LlmAgentConfig(model="claude-haiku-4-5", api_key="x")
    sentinel = MagicMock()
    with patch("appsec_crew.triage_llm._CrewAILLM", sentinel):
        out = llm_triage_batch(cfg, agent_role="x", items=[], guidance="g")
    assert out == []
    sentinel.assert_not_called()


def test_triage_no_api_key_short_circuits() -> None:
    cfg = LlmAgentConfig(model="claude-haiku-4-5", api_key="")
    sentinel = MagicMock()
    with patch("appsec_crew.triage_llm._CrewAILLM", sentinel):
        out = llm_triage_batch(cfg, agent_role="x", items=[{"index": 0}], guidance="g")
    assert out == []
    sentinel.assert_not_called()


def test_triage_returns_empty_when_crewai_not_importable() -> None:
    """If crewai itself is missing (stripped-down dev env, broken install),
    the triage logs an ERROR and fails-open. This is the regression that
    showed up in CI when LiteLLM wasn't a transitive crewai dep anymore —
    we want a loud signal instead of silently '0 dismissals'."""
    cfg = LlmAgentConfig(model="claude-sonnet-4-6", api_key="sk-x")
    with patch("appsec_crew.triage_llm._CrewAILLM", None):
        out = llm_triage_batch(cfg, agent_role="x", items=[{"index": 0}], guidance="g")
    assert out == []
