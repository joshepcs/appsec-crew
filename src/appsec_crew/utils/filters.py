"""Filter scanner output by minimum severity (exceptions live in each tool's own config file)."""

from __future__ import annotations

from typing import Any, Callable

from appsec_crew.utils.severity import semgrep_finding_rank, min_rank_for_semgrep


def filter_osv_by_min_cvss(
    results: list[dict[str, Any]],
    cvss_min: float,
    score_fn: Callable[[dict[str, Any]], float | None],
    include_no_score: bool,
) -> list[dict[str, Any]]:
    """Keep packages with at least one vulnerability at or above the CVSS floor (or unknown if allowed)."""
    filtered: list[dict[str, Any]] = []
    for block in results:
        vulns = block.get("vulnerabilities") or []
        kept: list[dict[str, Any]] = []
        for v in vulns:
            if not isinstance(v, dict):
                continue
            sc = score_fn(v)
            if sc is None:
                if include_no_score:
                    kept.append(v)
                continue
            if sc >= cvss_min:
                kept.append(v)
        if kept:
            nb = dict(block)
            nb["vulnerabilities"] = kept
            filtered.append(nb)
    return filtered


def filter_semgrep_by_min_severity(findings: list[dict[str, Any]], min_level: str) -> list[dict[str, Any]]:
    need = min_rank_for_semgrep(min_level)
    return [f for f in findings if semgrep_finding_rank(f) >= need]
