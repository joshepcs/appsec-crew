"""Process-wide context for tools (set from main before Crew kickoff)."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from appsec_crew.settings import AppSecSettings


@dataclass
class RuntimeContext:
    settings: AppSecSettings
    repo_path: Path
    state: dict[str, Any] = field(default_factory=dict)
    github_event: dict[str, Any] | None = None
    pr_number: int | None = None
    #: From ``GITHUB_EVENT_NAME`` (e.g. ``pull_request``, ``schedule``). Drives PR-comment vs batch Issues/PRs.
    github_event_name: str | None = None


CTX: RuntimeContext | None = None


def get_ctx() -> RuntimeContext:
    if CTX is None:
        raise RuntimeError("RuntimeContext not initialized; call set_runtime_context() first.")
    return CTX


def set_runtime_context(ctx: RuntimeContext) -> None:
    global CTX
    CTX = ctx


def reset_runtime_context() -> None:
    global CTX
    CTX = None
