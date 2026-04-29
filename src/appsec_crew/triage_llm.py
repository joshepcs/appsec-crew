"""Optional LLM pass to flag likely false positives before acting on scanner output.

Routing
-------

The triage call goes through ``crewai.LLM`` — the same dispatch path the
main agents use via :mod:`appsec_crew.utils.llm`. This is critical because:

* CrewAI 1.10+ does NOT bundle LiteLLM as a transitive dependency (it ships
  ``openai`` and ``anthropic`` directly as native providers). A previous
  iteration of this module called ``litellm.completion`` directly and broke
  in CI when LiteLLM wasn't installed (``ModuleNotFoundError: No module
  named 'litellm'``).
* Reusing ``crewai.LLM`` means the agent and the triage share one code path,
  one set of credentials, one model-resolution policy. Whatever works for
  the agent works for triage.

Routing rules honored (same as :func:`appsec_crew.utils.llm.build_llm`):

* ``model: gpt-*`` → OpenAI (default).
* ``model: claude-*`` → auto-prefixed to ``anthropic/...`` so CrewAI's native
  dispatcher picks the Anthropic provider (without the prefix it falls
  through to OpenAI and 401s on an Anthropic key — see commit cb80285).
* ``model: gemini-*`` → Google Gemini.
* ``model: github/*`` (already prefixed) → passes through.
* ``base_url`` is honored for OpenAI-compatible endpoints (Azure, vLLM,
  GH Models, etc.).
"""

from __future__ import annotations

import json
import re
from typing import Any

from appsec_crew.settings import LlmAgentConfig
from appsec_crew.utils.llm_routing import resolve_model_for_litellm
from appsec_crew.utils.logger import get_logger

_log = get_logger("appsec_crew.triage")

# CrewAI is a hard dep of this package (declared in pyproject.toml). The lazy
# import + ImportError capture mirrors the rest of the codebase's defensive
# pattern: the triage module stays importable even in stripped-down test
# environments that don't have crewai installed (utils.llm_routing tests).
try:
    from crewai import LLM as _CrewAILLM
    _CREWAI_IMPORT_ERROR: str | None = None
except ImportError as _e:  # pragma: no cover
    _CrewAILLM = None  # type: ignore[assignment]
    _CREWAI_IMPORT_ERROR = repr(_e)


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
    if _CrewAILLM is None:
        _log.error(
            "triage: crewai not importable, skipping triage for %d item(s). "
            "ImportError was: %s",
            len(items),
            _CREWAI_IMPORT_ERROR,
        )
        return []

    model = resolve_model_for_litellm(cfg.model, cfg.base_url, cfg.provider)
    _log.debug(
        "triage: dispatching via crewai.LLM model=%s base_url=%s provider=%s",
        model, cfg.base_url, cfg.provider,
    )
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
        # Construct LLM with the same shape :func:`build_llm` uses, so the
        # triage call inherits whatever fix the main agent path needs (e.g.
        # the ``anthropic/`` prefix added by ``resolve_model_for_litellm``).
        llm_kwargs: dict[str, Any] = dict(cfg.extra)
        llm_kwargs["api_key"] = cfg.api_key
        llm_kwargs["temperature"] = min(cfg.temperature, 0.3)
        if cfg.base_url:
            llm_kwargs["base_url"] = cfg.base_url
        if cfg.provider:
            llm = _CrewAILLM(model=model, provider=cfg.provider, **llm_kwargs)
        else:
            llm = _CrewAILLM(model=model, **llm_kwargs)
        # crewai.LLM.call returns the model's response as a string directly.
        content = llm.call(
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ]
        )
        if not isinstance(content, str) or not content:
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
    except Exception as e:
        # Surface the failure so triage no longer silently 'returns 0 dismissals'
        # when the call itself broke. We still fail-open (return []) so the
        # security scanner never drops findings on a bad LLM call — but the log
        # now tells you why it dropped to 0.
        resp_body = ""
        resp = getattr(e, "response", None)
        if resp is not None:
            try:
                resp_body = (resp.text if hasattr(resp, "text") else str(resp))[:2000]
            except Exception:
                resp_body = "(could not read response body)"
        _log.error(
            "triage: LLM call failed (model=%s base_url=%s): %s: %s%s",
            model,
            cfg.base_url,
            type(e).__name__,
            str(e)[:500],
            f" | response_body={resp_body}" if resp_body else "",
        )
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
