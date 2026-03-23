"""Extract numeric CVSS scores from OSV-style severity blobs."""

from __future__ import annotations

from typing import Any


def max_cvss_score(vuln: dict[str, Any]) -> float | None:
    """Return the highest CVSS score found on an OSV vulnerability object."""
    severities = vuln.get("severity") or []
    best: float | None = None
    for s in severities:
        if not isinstance(s, dict):
            continue
        if s.get("type") != "CVSS_V3" and s.get("type") != "CVSS_V31":
            continue
        score = s.get("score")
        if score is None:
            continue
        try:
            val = float(score)
        except (TypeError, ValueError):
            continue
        best = val if best is None else max(best, val)
    return best


def severity_bucket(score: float | None) -> str:
    if score is None:
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def is_high_or_critical(score: float | None, minimum: float = 7.0) -> bool:
    if score is None:
        return False
    return score >= minimum
