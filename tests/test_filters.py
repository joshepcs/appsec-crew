"""Tests for OSV / Semgrep result filters."""

from __future__ import annotations

from appsec_crew.utils.cvss import max_cvss_score
from appsec_crew.utils.filters import filter_osv_by_min_cvss


def test_filter_osv_by_min_cvss_keeps_above_floor() -> None:
    results = [
        {
            "package": {"name": "x"},
            "vulnerabilities": [
                {"id": "1", "severity": [{"type": "CVSS_V3", "score": "9.0"}]},
                {"id": "2", "severity": [{"type": "CVSS_V3", "score": "3.0"}]},
            ],
        }
    ]
    out = filter_osv_by_min_cvss(results, 7.0, max_cvss_score, include_no_score=False)
    assert len(out) == 1
    assert len(out[0]["vulnerabilities"]) == 1
    assert out[0]["vulnerabilities"][0]["id"] == "1"


def test_filter_osv_include_no_score() -> None:
    results = [
        {
            "vulnerabilities": [
                {"id": "u", "severity": []},
            ],
        }
    ]
    out = filter_osv_by_min_cvss(results, 7.0, max_cvss_score, include_no_score=True)
    assert len(out) == 1
    assert out[0]["vulnerabilities"][0]["id"] == "u"


def test_filter_osv_skips_non_dict_vulnerabilities() -> None:
    results = [{"vulnerabilities": [None, "bad", {"id": "ok", "severity": [{"type": "CVSS_V3", "score": "9.0"}]}]}]
    out = filter_osv_by_min_cvss(results, 7.0, max_cvss_score, include_no_score=False)
    assert len(out) == 1
    assert out[0]["vulnerabilities"][0]["id"] == "ok"


def test_filter_osv_drops_block_when_no_vuln_matches() -> None:
    results = [
        {
            "vulnerabilities": [
                {"id": "low", "severity": [{"type": "CVSS_V3", "score": "2.0"}]},
            ],
        }
    ]
    out = filter_osv_by_min_cvss(results, 7.0, max_cvss_score, include_no_score=False)
    assert out == []
