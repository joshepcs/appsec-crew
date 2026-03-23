"""Generic webhook POST."""

from __future__ import annotations

from typing import Any

import httpx


def post_json(url: str, payload: dict[str, Any], headers: dict[str, str] | None = None) -> None:
    h = {"Content-Type": "application/json", **(headers or {})}
    r = httpx.post(url, json=payload, headers=h, timeout=60.0)
    r.raise_for_status()
