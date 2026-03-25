#!/usr/bin/env python
"""CLI entry: load config, ensure tool configs, run CrewAI crew, validate."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from appsec_crew.crew import build_appsec_crew
from appsec_crew.utils.llm import crew_llm_ready
from appsec_crew.pipelines import (
    _is_pr_scan_mode,
    pr_scan_has_actionable_findings,
    pr_scan_summary_for_ci,
    validate_postconditions,
)
from appsec_crew.runtime import RuntimeContext, reset_runtime_context, set_runtime_context
from appsec_crew.settings import ensure_tool_config_files, load_settings, resolve_appsec_config_path


def _load_github_event() -> tuple[dict, int | None]:
    path = os.environ.get("GITHUB_EVENT_PATH")
    if not path:
        return {}, None
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}, None
    pr = data.get("pull_request") or {}
    num = pr.get("number")
    return data, int(num) if num is not None else None


def _defaults_dir() -> Path:
    return Path(__file__).resolve().parent / "defaults"


def run_once(repo: Path, config_path: Path, used_bundled_fallback: bool) -> int:
    settings = load_settings(config_path)
    ensured = ensure_tool_config_files(repo, settings, _defaults_dir())

    event, pr_number = _load_github_event()
    if pr_number is None:
        pr_env = os.environ.get("APPSEC_CREW_PR_NUMBER")
        if pr_env and pr_env.isdigit():
            pr_number = int(pr_env)

    ctx = RuntimeContext(
        settings=settings,
        repo_path=repo.resolve(),
        state={},
        github_event=event,
        pr_number=pr_number,
        github_event_name=os.environ.get("GITHUB_EVENT_NAME"),
    )
    set_runtime_context(ctx)

    try:
        if not crew_llm_ready(settings):
            print(
                "CrewAI requires an LLM API key for every enabled agent. "
                "Set llm.api_key or llm.api_key_env (e.g. OPENAI_API_KEY) in appsec_crew.yaml.",
                file=sys.stderr,
            )
            return 3

        crew = build_appsec_crew(ctx)
        crew.kickoff(inputs={})

        errs = validate_postconditions(ctx)
        if errs:
            print("Validation checklist failed:", file=sys.stderr)
            for e in errs:
                print(f"  - {e}", file=sys.stderr)
            return 2

        if _is_pr_scan_mode(ctx) and pr_scan_has_actionable_findings(ctx):
            md = pr_scan_summary_for_ci(ctx)
            if md.strip():
                print("\n--- Reporter ---\n")
                print(md)
            print(
                "Pull request scan failed: actionable security findings remain after filters/triage. "
                "See the PR comment (if reporter is enabled) for counts and where to add tool-native exceptions "
                "(.betterleaks.toml / .gitleaks.toml, osv-scanner.toml, .semgrep.yml).",
                file=sys.stderr,
            )
            return 5

        print("AppSec Crew completed. Tool configs ensured:", json.dumps(ensured, indent=2))
        if used_bundled_fallback:
            print(
                "Config: bundled default (no appsec_crew.yaml in repo; reporter Jira/webhook/Splunk disabled).",
                file=sys.stderr,
            )
        rep = ctx.state.get("reporter") or {}
        if rep.get("markdown"):
            print("\n--- Reporter ---\n")
            print(rep["markdown"])
        return 0
    finally:
        reset_runtime_context()


def main() -> None:
    p = argparse.ArgumentParser(
        description="AppSec Crew — security automation (CrewAI). "
        "Without --config: uses appsec_crew.yaml in --repo, else bundled default."
    )
    p.add_argument(
        "--repo",
        type=Path,
        default=Path(os.environ.get("APPSEC_CREW_REPO", ".")),
        help="Path to the repository to scan (default: . or APPSEC_CREW_REPO)",
    )
    p.add_argument(
        "--config",
        type=Path,
        default=None,
        metavar="PATH",
        help="Path to appsec_crew.yaml (optional). If omitted: <repo>/appsec_crew.yaml, then APPSEC_CREW_CONFIG, then bundled default.",
    )
    args = p.parse_args()

    try:
        cfg_path, bundled = resolve_appsec_config_path(args.repo, args.config)
    except FileNotFoundError as e:
        print(str(e), file=sys.stderr)
        raise SystemExit(4) from e

    code = run_once(args.repo, cfg_path, bundled)
    raise SystemExit(code)


if __name__ == "__main__":
    main()
