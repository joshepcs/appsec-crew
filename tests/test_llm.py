"""Tests for LLM helper (no live API calls)."""

from __future__ import annotations

from appsec_crew.settings import LlmAgentConfig
from appsec_crew.utils.llm import build_llm


def test_build_llm_returns_none_without_api_key() -> None:
    cfg = LlmAgentConfig(api_key=None, api_key_env="MISSING_ENV_XYZ")
    assert build_llm(cfg) is None


def test_build_llm_returns_none_for_empty_string_key() -> None:
    cfg = LlmAgentConfig(api_key="")
    assert build_llm(cfg) is None
