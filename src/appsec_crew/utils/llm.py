"""Construct CrewAI LLM clients from YAML agent settings."""

from __future__ import annotations

from crewai import LLM

from appsec_crew.settings import AppSecSettings, LlmAgentConfig
from appsec_crew.utils.llm_routing import (
    LITELLM_PREFIX_MAP as _LITELLM_PREFIX_MAP,  # re-export for back-compat
    resolve_model_for_litellm,
)

# Backwards-compatible alias for callers that already import the underscored
# name from this module.
_resolve_model = resolve_model_for_litellm


def build_llm(cfg: LlmAgentConfig) -> LLM | None:
    key = cfg.api_key
    if not key:
        return None
    # Same kwargs shape for every agent; unknown YAML keys live in cfg.extra (see _parse_llm).
    kwargs: dict = dict(cfg.extra)
    kwargs["api_key"] = key
    kwargs["temperature"] = cfg.temperature
    if cfg.base_url:
        kwargs["base_url"] = cfg.base_url
    model = _resolve_model(cfg.model, cfg.base_url, cfg.provider)
    if cfg.provider:
        return LLM(model=model, provider=cfg.provider, **kwargs)
    return LLM(model=model, **kwargs)


def crew_llm_ready(settings: AppSecSettings) -> bool:
    """True if at least one agent is enabled and every enabled agent has a resolved LLM API key."""
    any_enabled = False
    for block in (
        settings.secrets_reviewer,
        settings.dependencies_reviewer,
        settings.code_reviewer,
        settings.reporter,
    ):
        if not block.enabled:
            continue
        any_enabled = True
        if not block.llm.api_key:
            return False
    return any_enabled
