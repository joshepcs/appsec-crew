"""Emit scanner install versions from `appsec_crew.yaml` (per-tool ``version`` fields) for GitHub Actions."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from appsec_crew.settings import load_settings, resolve_appsec_config_path


def _write_github_output(name: str, value: str) -> None:
    path = os.environ.get("GITHUB_OUTPUT")
    line = f"{name}={value}\n"
    if path:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(line)
    else:
        sys.stdout.write(line)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--repo",
        required=True,
        type=Path,
        help="Scanned repository root (same as appsec-crew --repo)",
    )
    p.add_argument(
        "--config",
        type=str,
        default="",
        help="Optional config path (relative to cwd or absolute), same semantics as appsec-crew --config",
    )
    args = p.parse_args(argv)

    repo = args.repo.expanduser().resolve()
    explicit: Path | None = None
    if args.config.strip():
        explicit = Path(args.config.strip()).expanduser()

    cfg_path, _bundled = resolve_appsec_config_path(repo, explicit)
    tv = load_settings(cfg_path).tool_versions

    _write_github_output("betterleaks_version", tv.betterleaks)
    _write_github_output("osv_scanner_version", tv.osv_scanner)
    _write_github_output("semgrep_version", tv.semgrep)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
