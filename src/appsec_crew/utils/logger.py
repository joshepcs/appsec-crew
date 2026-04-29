"""Shared logging setup for AppSec Crew.

Silent by default — only WARNING+ surfaces. Diagnostic traces (the per-finding
review tracing, the PR-paths echo, the body_len/commit_id lines, etc.) live at
DEBUG and INFO and stay quiet unless explicitly enabled.

Configuration:

* ``APPSEC_CREW_LOG_LEVEL`` (str): one of ``DEBUG``, ``INFO``, ``WARNING``,
  ``ERROR``, ``CRITICAL``. Defaults to ``WARNING``.

Usage in a module::

    from appsec_crew.utils.logger import get_logger
    log = get_logger("appsec_crew.review")
    log.debug("findings=%d inline_comments=%d", n, m)

Logs go to stderr, prefixed ``[appsec-crew][<logger-name-tail>] <message>`` so
GitHub Actions output stays grep-able with the same pattern as the previous
print-based instrumentation.
"""

from __future__ import annotations

import logging
import os
import sys

_ROOT_NAME = "appsec_crew"
_CONFIGURED = False


def _resolve_level() -> int:
    raw = os.environ.get("APPSEC_CREW_LOG_LEVEL", "").strip().upper()
    if not raw:
        return logging.WARNING
    return getattr(logging, raw, logging.WARNING)


class _AppSecFormatter(logging.Formatter):
    """Format ``appsec_crew.review`` -> ``[appsec-crew][review]``.

    Strips the ``appsec_crew.`` prefix so the output matches the historical
    ``[appsec-crew][semgrep-review]`` style that ops dashboards already grep.
    """

    def format(self, record: logging.LogRecord) -> str:
        tail = record.name
        if tail.startswith(_ROOT_NAME + "."):
            tail = tail[len(_ROOT_NAME) + 1 :]
        elif tail == _ROOT_NAME:
            tail = "core"
        record.tail = tail
        return f"[appsec-crew][{tail}] {record.getMessage()}"


def _ensure_configured() -> None:
    """Idempotent root-logger setup. Safe to call from anywhere."""
    global _CONFIGURED
    if _CONFIGURED:
        return
    root = logging.getLogger(_ROOT_NAME)
    # Only attach our handler if the consumer hasn't already wired one. This
    # avoids double-output when something embedding AppSec Crew (CrewAI flows,
    # tests using caplog, etc.) configured logging upstream.
    if not root.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(_AppSecFormatter())
        root.addHandler(handler)
    root.setLevel(_resolve_level())
    root.propagate = False
    _CONFIGURED = True


def get_logger(name: str | None = None) -> logging.Logger:
    """Return an AppSec-Crew-scoped logger configured from the environment."""
    _ensure_configured()
    return logging.getLogger(name or _ROOT_NAME)
