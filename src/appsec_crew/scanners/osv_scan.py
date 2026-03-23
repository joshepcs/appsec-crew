"""Run OSV-Scanner (v1-style CLI) and flatten package vulnerability rows."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

from appsec_crew.utils.cvss import max_cvss_score


def _flatten_osv_results(data: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for block in data.get("results") or []:
        if not isinstance(block, dict):
            continue
        packages = block.get("packages")
        if isinstance(packages, list):
            for pkg_block in packages:
                if isinstance(pkg_block, dict):
                    rows.append(pkg_block)
        else:
            pkg = block.get("package")
            vulns = block.get("vulnerabilities")
            if isinstance(pkg, dict) and isinstance(vulns, list):
                rows.append({"package": pkg, "vulnerabilities": vulns})
    return rows


def run_osv_scan(
    repo: Path,
    binary: str,
    config_path: Path | None,
    report_path: Path,
) -> list[dict[str, Any]]:
    cmd = [binary, "scan", "-r", "-f", "json", "--output", str(report_path), str(repo)]
    if config_path and config_path.is_file():
        cmd[2:2] = ["--config", str(config_path)]

    subprocess.run(cmd, cwd=str(repo), text=True, capture_output=True)

    if not report_path.is_file():
        return []
    raw = report_path.read_text(encoding="utf-8", errors="replace").strip()
    if not raw:
        return []
    data = json.loads(raw)
    if not isinstance(data, dict):
        return []
    return _flatten_osv_results(data)


def high_critical_rows(rows: list[dict[str, Any]], cvss_min: float) -> list[dict[str, Any]]:
    """Keep rows that have at least one vulnerability with CVSS >= cvss_min."""
    out: list[dict[str, Any]] = []
    for row in rows:
        vulns = [v for v in (row.get("vulnerabilities") or []) if isinstance(v, dict)]
        scores = [max_cvss_score(v) for v in vulns]
        scores = [s for s in scores if s is not None]
        if scores and max(scores) >= cvss_min:
            out.append(row)
    return out


def discover_remediation_targets(repo: Path) -> list[tuple[str, Path]]:
    """
    Return (strategy_hint, path) for osv-scanner fix.
    strategy_hint: lockfile | manifest
    """
    targets: list[tuple[str, Path]] = []
    for pattern, hint in (
        ("package-lock.json", "lockfile"),
        ("pnpm-lock.yaml", "lockfile"),
        ("yarn.lock", "lockfile"),
        ("pom.xml", "manifest"),
    ):
        for p in repo.rglob(pattern):
            if ".git" in p.parts or "node_modules" in p.parts:
                continue
            targets.append((hint, p))
    return targets


def run_osv_fix_inplace(lockfile: Path, binary: str, min_severity: float) -> subprocess.CompletedProcess[str]:
    cmd = [
        binary,
        "fix",
        "--non-interactive",
        "--strategy",
        "in-place",
        "--min-severity",
        str(min_severity),
        "-L",
        str(lockfile),
    ]
    return subprocess.run(cmd, cwd=str(lockfile.parent), text=True, capture_output=True)


def run_osv_fix_override_pom(pom: Path, binary: str, min_severity: float) -> subprocess.CompletedProcess[str]:
    cmd = [
        binary,
        "fix",
        "--non-interactive",
        "--strategy",
        "override",
        "--min-severity",
        str(min_severity),
        "-M",
        str(pom),
    ]
    return subprocess.run(cmd, cwd=str(pom.parent), text=True, capture_output=True)
