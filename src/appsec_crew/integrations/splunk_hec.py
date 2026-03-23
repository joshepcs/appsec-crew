"""Splunk HTTP Event Collector (HEC)."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import httpx


def send_event(
    hec_url: str,
    token: str,
    event: dict[str, Any],
    source: str,
    sourcetype: str,
) -> None:
    """POST one JSON event to HEC (raw endpoint)."""
    body = {
        "time": datetime.now(timezone.utc).timestamp(),
        "source": source,
        "sourcetype": sourcetype,
        "event": event,
    }
    r = httpx.post(
        hec_url.rstrip("/"),
        json=body,
        headers={"Authorization": f"Splunk {token}"},
        timeout=60.0,
    )
    r.raise_for_status()
