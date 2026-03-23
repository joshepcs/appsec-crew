"""Run Betterleaks and parse JSON report."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any


def run_betterleaks_scan(
    repo: Path,
    binary: str,
    config_path: Path | None,
    report_path: Path,
) -> list[dict[str, Any]]:
    cmd = [binary, "dir", "--no-banner"]
    if config_path and config_path.is_file():
        cmd += ["-c", str(config_path)]
    cmd += ["-f", "json", "-r", str(report_path), str(repo)]

    subprocess.run(cmd, cwd=str(repo), text=True, capture_output=True)
    # exit 1 = leaks found; still write report
    if not report_path.is_file():
        return []
    raw = report_path.read_text(encoding="utf-8", errors="replace").strip()
    if not raw:
        return []
    data = json.loads(raw)
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    if isinstance(data, dict):
        for key in ("findings", "leaks", "results", "Issues"):
            v = data.get(key)
            if isinstance(v, list):
                return [x for x in v if isinstance(x, dict)]
    return []
