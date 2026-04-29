"""Optional LLM pass to flag likely false positives before acting on scanner output.

Routing
-------

The triage call goes through **LiteLLM** (a transitive dependency of CrewAI),
the same dispatch path the main agents use via :mod:`appsec_crew.utils.llm`.
This means the YAML config is honored consistently:

* ``model: gpt-*`` → OpenAI (default).
* ``model: claude-*`` → auto-prefixed to ``anthropic/...`` and dispatched to
  the Anthropic API with the right schema (``/v1/messages`` + ``x-api-key``).
* ``model: gemini-*`` → Google Gemini.
* ``model: github/*`` (already prefixed) → passes through; LiteLLM dispatches
  to GitHub Models.
* ``base_url`` is honored verbatim for OpenAI-compatible endpoints (Azure
  OpenAI, vLLM, OpenRouter, GH Models, etc.).

Before this change the triage spoke raw OpenAI ``/v1/chat/completions``
unconditionally — Anthropic-keyed runs got 401 silently, the empty result
was caught and turned into "0 dismissals", and triage looked like it ran but
never actually changed anything. The fix is exactly the same routing the
agents already use, just lifted into this module.
"""

from __future__ import annotations

import json
import re
from typing import Any

from appsec_crew.settings import LlmAgentConfig
from appsec_crew.utils.llm_routing import resolve_model_for_litellm

# LiteLLM ships as a transitive dep of CrewAI (>= 1.10). Lazy import lets the
# module fail gracefully (return [] from llm_triage_batch) if it is somehow
# absent, instead of breaking module import for callers that never trigger
# triage (llm_triage opt-in).
try:
    from litellm import completion as _litellm_completion
except ImportError:  # pragma: no cover
    _litellm_completion = None  # type: ignore[assignment]


def _extract_json_object(text: str) -> dict[str, Any] | None:
    t = text.strip()
    m = re.search(r"\{[\s\S]*\}\s*$", t)
    if m:
        try:
            return json.loads(m.group(0))
        except json.JSONDecodeError:
            pass
    fence = re.search(r"```(?:json)?\s*([\s\S]*?)```", t)
    if fence:
        try:
            return json.loads(fence.group(1).strip())
        except json.JSONDecodeError:
            return None
    try:
        return json.loads(t)
    except json.JSONDecodeError:
        return None


def llm_triage_batch(
    cfg: LlmAgentConfig,
    *,
    agent_role: str,
    items: list[dict[str, Any]],
    guidance: str,
    timeout_s: float = 120.0,
) -> list[dict[str, Any]]:
    """Ask the configured LLM which item indices are likely false positives.

    Returns a list of dicts: ``[{"index": <int>, "reason": "<short>"}, ...]``
    (only dismissed items). On any failure — bad credentials, network error,
    malformed response, parse failure — returns ``[]`` so the caller keeps
    every finding (fail-open is the safe default for a security scanner).
    """
    if not cfg.api_key or not items:
        return []
    if _litellm_completion is None:
        return []

    model = resolve_model_for_litellm(cfg.model, cfg.base_url, cfg.provider)
    system = (
        f"You are {agent_role}. Review scanner candidates and mark likely false positives only. "
        "Never request or invent secret values. Respond with JSON only."
    )
    user = (
        guidance
        + "\n\nItems (index is stable):\n"
        + json.dumps(items[:80], indent=2, ensure_ascii=False)
        + '\n\nRespond with JSON: {"dismiss": [{"index": <int>, "reason": "<short>"}]} '
        "Use empty dismiss if none apply."
    )
    try:
        kwargs: dict[str, Any] = {
            "model": model,
            "api_key": cfg.api_key,
            "temperature": min(cfg.temperature, 0.3),
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "timeout": timeout_s,
        }
        if cfg.base_url:
            kwargs["base_url"] = cfg.base_url
        response = _litellm_completion(**kwargs)
        # LiteLLM normalizes responses to the OpenAI shape across providers.
        choices = getattr(response, "choices", None) or []
        if not choices:
            return []
        message = getattr(choices[0], "message", None)
        content = (getattr(message, "content", None) or "") if message else ""
        if not isinstance(content, str):
            return []
        parsed = _extract_json_object(content)
        if not parsed:
            return []
        out: list[dict[str, Any]] = []
        for row in parsed.get("dismiss") or []:
            if not isinstance(row, dict):
                continue
            try:
                idx = int(row["index"])
            except (KeyError, TypeError, ValueError):
                continue
            reason = str(row.get("reason") or "dismissed by triage")[:500]
            out.append({"index": idx, "reason": reason})
        return out
    except Exception:
        return []


def partition_by_dismiss_indices(
    findings: list[dict[str, Any]],
    dismiss_meta: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Split findings into kept vs dismissed using 0-based indices from triage."""
    reason_by_idx: dict[int, str] = {}
    for d in dismiss_meta:
        try:
            reason_by_idx[int(d["index"])] = str(d.get("reason") or "triage")[:500]
        except (KeyError, TypeError, ValueError):
            continue
    kept: list[dict[str, Any]] = []
    dismissed: list[dict[str, Any]] = []
    for i, f in enumerate(findings):
        if i in reason_by_idx:
            dismissed.append({**f, "_dismiss_reason": reason_by_idx[i]})
        else:
            kept.append(f)
    return kept, dismissed
