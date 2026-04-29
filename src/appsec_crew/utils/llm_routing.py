"""Pure-Python LiteLLM model-routing helpers.

Lives here (separate from :mod:`appsec_crew.utils.llm`) so it has zero CrewAI
import cost — both the agent builder (``utils.llm.build_llm``) and the
triage module (``triage_llm``) can use the same routing rules without
forcing CrewAI into modules that don't otherwise need it (and without
breaking unit tests that don't have CrewAI installed).
"""

from __future__ import annotations

# Map of bare model-name prefixes → LiteLLM provider prefix.
#
# Why this exists: CrewAI 1.10+ has a "native provider" path that picks up
# bare ``claude-*`` strings and dispatches them through the OpenAI native
# provider (which then sends an Anthropic key to api.openai.com and 401s).
# Prefixing the model with ``anthropic/`` forces LiteLLM to handle the call
# directly with the right wire format and credentials.
LITELLM_PREFIX_MAP: dict[str, str] = {
    "claude-": "anthropic",
    "gemini-": "gemini",
}


def resolve_model_for_litellm(
    model: str, base_url: str | None, provider: str | None
) -> str:
    """Add a LiteLLM provider prefix to bare model strings when no explicit
    provider, base_url override, or pre-existing provider prefix is set.

    Examples::

        resolve_model_for_litellm("claude-sonnet-4-6", None, None)
        -> "anthropic/claude-sonnet-4-6"

        resolve_model_for_litellm("gpt-4o-mini", None, None)
        -> "gpt-4o-mini"   # OpenAI default, no prefix needed

        resolve_model_for_litellm("github/gpt-4o", None, None)
        -> "github/gpt-4o" # already prefixed, leave alone

        resolve_model_for_litellm("claude-haiku-4-5",
                                  base_url="https://my.proxy/", provider=None)
        -> "claude-haiku-4-5"  # base_url overrides — caller picked the route
    """
    if provider or base_url or "/" in model:
        return model
    for prefix, litellm_provider in LITELLM_PREFIX_MAP.items():
        if model.startswith(prefix):
            return f"{litellm_provider}/{model}"
    return model
