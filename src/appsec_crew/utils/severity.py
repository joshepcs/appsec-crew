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
    """
    Map Semgrep JSON finding to a numeric rank.

    Registry rules often omit ``extra.severity``; those used to default to WARNING (rank 2) and were then
    dropped when ``global.min_severity`` was ``high`` (needs rank ≥ 4). Missing severity is treated as **HIGH**
    so unlabeled findings are still actionable at the ``high`` threshold; explicit ``INFO`` / ``LOW`` stay low.
    """
    raw_ex = finding.get("extra")
    extra = raw_ex if isinstance(raw_ex, dict) else {}
    meta = extra.get("metadata") if isinstance(extra.get("metadata"), dict) else {}
    sev = (extra.get("severity") or "").strip().upper()
    if not sev and meta.get("severity") is not None:
        sev = str(meta["severity"]).strip().upper()
    if not sev and finding.get("severity") is not None:
        sev = str(finding["severity"]).strip().upper()
    if not sev:
        return _SEMGREP_RANK["HIGH"]
    return _SEMGREP_RANK.get(sev, _SEMGREP_RANK["WARNING"])


def min_rank_for_semgrep(level: str) -> int:
    return _MIN_SEVERITY_SEMGREP_RANK.get(level.lower(), 4)


def human_severity_label(level: str) -> str:
    return level.upper()
