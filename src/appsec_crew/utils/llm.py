"""Construct CrewAI LLM clients from YAML agent settings."""

from __future__ import annotations

from crewai import LLM

from appsec_crew.settings import AppSecSettings, LlmAgentConfig

# Map of model prefixes → LiteLLM provider prefix.
# CrewAI 1.10+ auto-detects native providers from model strings (e.g. "claude-*" →
# crewai[anthropic] native provider). The native Anthropic provider delegates to
# crewai/llms/providers/openai/completion.py internally, which then sends the
# Anthropic API key to api.openai.com and fails with 401.
# Workaround: prefix the model with "anthropic/" so LiteLLM handles the call
# directly (bypassing the native provider path entirely).
_LITELLM_PREFIX_MAP: dict[str, str] = {
    "claude-": "anthropic",
    "gemini-": "gemini",
}


def _resolve_model(model: str, base_url: str | None, provider: str | None) -> str:
    """
    Add a LiteLLM provider prefix to bare model strings when no explicit
    provider or base_url override is set.

    Examples:
        "claude-sonnet-4-6"          → "anthropic/claude-sonnet-4-6"
        "claude-haiku-4-5-20251001"  → "anthropic/claude-haiku-4-5-20251001"
        "gpt-4o-mini"                → "gpt-4o-mini"  (OpenAI default, no prefix needed)
        "anthropic/claude-sonnet-4-6"→ "anthropic/claude-sonnet-4-6"  (already prefixed)
    """
    # Don't touch if: explicit provider set, custom base_url, or already prefixed.
    if provider or base_url or "/" in model:
        return model
    for prefix, litellm_provider in _LITELLM_PREFIX_MAP.items():
        if model.startswith(prefix):
            return f"{litellm_provider}/{model}"
    return model


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
