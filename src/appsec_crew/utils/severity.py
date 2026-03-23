"""Map user-facing min_severity (critical|high|medium|low) to CVSS floors and Semgrep ranks."""

from __future__ import annotations

# CVSS v3 approximate bands: LOW 0.1–3.9, MEDIUM 4.0–6.9, HIGH 7.0–8.9, CRITICAL 9.0–10.0
MIN_SEVERITY_CVSS_FLOOR: dict[str, float] = {
    "critical": 9.0,
    "high": 7.0,
    "medium": 4.0,
    "low": 0.0,
}


def cvss_floor_for_min_severity(level: str) -> float:
    return MIN_SEVERITY_CVSS_FLOOR.get(level.lower(), 7.0)


def include_osv_vuln_without_cvss(level: str) -> bool:
    """When minimum is `low`, keep OSV entries that have no CVSS score."""
    return level.lower() == "low"


# Semgrep: rank findings; higher = more severe
_SEMGREP_RANK: dict[str, int] = {
    "CRITICAL": 5,
    "HIGH": 4,
    "ERROR": 4,
    "MEDIUM": 3,
    "WARNING": 2,
    "LOW": 1,
    "INFO": 0,
}

# Minimum user level -> minimum rank required (inclusive)
_MIN_SEVERITY_SEMGREP_RANK: dict[str, int] = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 0,
}


def semgrep_finding_rank(finding: dict) -> int:
    extra = finding.get("extra") or {}
    sev = (extra.get("severity") or "").upper()
    meta = extra.get("metadata") or {}
    if meta.get("severity"):
        sev = str(meta["severity"]).upper()
    return _SEMGREP_RANK.get(sev, 2)


def min_rank_for_semgrep(level: str) -> int:
    return _MIN_SEVERITY_SEMGREP_RANK.get(level.lower(), 4)


def human_severity_label(level: str) -> str:
    return level.upper()
