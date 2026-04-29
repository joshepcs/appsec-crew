"""Triage routing tests.

The triage step previously POSTed raw OpenAI ``/v1/chat/completions`` regardless
of YAML config — so an Anthropic-keyed run silently got 401 and returned 0
dismissals. The new implementation dispatches via LiteLLM so the YAML model
prefix and base_url govern the destination, identically to how the main
agents are built (:func:`appsec_crew.utils.llm.build_llm`).
"""

from __future__ import annotations

import json
from unittest.mock import patch

from appsec_crew.settings import LlmAgentConfig
from appsec_crew.triage_llm import llm_triage_batch


def _stub_response(content: str):
    """Mimic the LiteLLM/OpenAI response shape with one choice's message.content."""
    class _Msg:
        def __init__(self, c: str) -> None:
            self.content = c

    class _Choice:
        def __init__(self, c: str) -> None:
            self.message = _Msg(c)

    class _Resp:
        def __init__(self, c: str) -> None:
            self.choices = [_Choice(c)]

    return _Resp(content)


def test_triage_routes_claude_via_anthropic_prefix() -> None:
    """A bare ``claude-*`` model in YAML must reach LiteLLM as ``anthropic/claude-*``,
    not as a raw model string posted to OpenAI."""
    cfg = LlmAgentConfig(model="claude-sonnet-4-6", api_key="sk-ant-xxx", temperature=0)
    captured = {}

    def fake_completion(**kw):
        captured.update(kw)
        return _stub_response('{"dismiss": []}')

    with patch("appsec_crew.triage_llm._litellm_completion", side_effect=fake_completion):
        out = llm_triage_batch(cfg, agent_role="x", items=[{"index": 0}], guidance="g")

    assert out == []
    # The model string sent to LiteLLM must include the anthropic/ prefix so
    # LiteLLM dispatches to api.anthropic.com (not api.openai.com).
    assert captured["model"] == "anthropic/claude-sonnet-4-6"
    # The Anthropic key is forwarded as `api_key`, not as a Bearer header.
    assert captured["api_key"] == "sk-ant-xxx"
    # No base_url override means LiteLLM picks the provider default.
    assert "base_url" not in captured


def test_triage_routes_gpt_models_to_openai_default() -> None:
    cfg = LlmAgentConfig(model="gpt-4o-mini", api_key="sk-openai", temperature=0)
    captured = {}

    def fake_completion(**kw):
        captured.update(kw)
        return _stub_response('{"dismiss": []}')

    with patch("appsec_crew.triage_llm._litellm_completion", side_effect=fake_completion):
        llm_triage_batch(cfg, agent_role="x", items=[{"index": 0}], guidance="g")

    # gpt-* models pass through unprefixed; LiteLLM will dispatch to OpenAI.
    assert captured["model"] == "gpt-4o-mini"


def test_triage_honors_base_url_for_compatible_endpoints() -> None:
    cfg = LlmAgentConfig(
        model="gpt-4o-mini",
        api_key="ghp_xxx",
        base_url="https://models.github.ai/inference",
        temperature=0,
    )
    captured = {}

    def fake_completion(**kw):
        captured.update(kw)
        return _stub_response('{"dismiss": []}')

    with patch("appsec_crew.triage_llm._litellm_completion", side_effect=fake_completion):
        llm_triage_batch(cfg, agent_role="x", items=[{"index": 0}], guidance="g")

    # base_url present → bypass _resolve_model auto-prefixing AND forward base_url.
    assert captured["model"] == "gpt-4o-mini"
    assert captured["base_url"] == "https://models.github.ai/inference"


def test_triage_returns_empty_when_completion_raises() -> None:
    """Fail-open: any LLM error keeps every finding instead of silently
    dropping them. Network errors, schema mismatches, anything."""
    cfg = LlmAgentConfig(model="claude-haiku-4-5", api_key="x", temperature=0)
    with patch("appsec_crew.triage_llm._litellm_completion", side_effect=RuntimeError("network")):
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
    with patch(
        "appsec_crew.triage_llm._litellm_completion",
        return_value=_stub_response(body),
    ):
        out = llm_triage_batch(cfg, agent_role="x", items=[{"index": i} for i in range(5)], guidance="g")

    assert {row["index"] for row in out} == {0, 2}
    assert all("reason" in row for row in out)
    assert out[0]["reason"].startswith("MD5 used for ETag")


def test_triage_empty_items_short_circuits() -> None:
    """Don't waste a roundtrip when there's nothing to triage."""
    cfg = LlmAgentConfig(model="claude-haiku-4-5", api_key="x")
    with patch("appsec_crew.triage_llm._litellm_completion") as fake:
        out = llm_triage_batch(cfg, agent_role="x", items=[], guidance="g")
    assert out == []
    fake.assert_not_called()


def test_triage_no_api_key_short_circuits() -> None:
    cfg = LlmAgentConfig(model="claude-haiku-4-5", api_key="")
    with patch("appsec_crew.triage_llm._litellm_completion") as fake:
        out = llm_triage_batch(cfg, agent_role="x", items=[{"index": 0}], guidance="g")
    assert out == []
    fake.assert_not_called()
