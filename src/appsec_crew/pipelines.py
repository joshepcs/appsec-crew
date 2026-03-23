"""Deterministic scan → GitHub issue/PR workflows (invoked by Crew tools)."""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from appsec_crew.git_ops import (
    commit_all,
    create_branch,
    ensure_identity,
    push_with_token,
)
from appsec_crew.integrations.github_api import GitHubApi
from appsec_crew.integrations.jira_api import JiraApi, upsert_appsec_ticket
from appsec_crew.integrations.splunk_hec import send_event
from appsec_crew.integrations.webhook_client import post_json
from appsec_crew.runtime import RuntimeContext
from appsec_crew.scanners.betterleaks_scan import run_betterleaks_scan
from appsec_crew.scanners.osv_scan import (
    discover_remediation_targets,
    run_osv_fix_inplace,
    run_osv_fix_override_pom,
    run_osv_scan,
)
from appsec_crew.scanners.semgrep_scan import build_semgrep_config_args, detect_primary_language, run_semgrep
from appsec_crew.settings import AppSecSettings
from appsec_crew.utils.cvss import max_cvss_score
from appsec_crew.utils.filters import filter_osv_by_min_cvss, filter_semgrep_by_min_severity
from appsec_crew.utils.severity import (
    cvss_floor_for_min_severity,
    human_severity_label,
    include_osv_vuln_without_cvss,
)


def _git_remote_host() -> str:
    u = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
    return u.replace("https://", "").replace("http://", "").rstrip("/")


def _github_client(settings: AppSecSettings) -> GitHubApi | None:
    tok = settings.github_token()
    repo = os.environ.get("GITHUB_REPOSITORY")
    if not tok or not repo:
        return None
    api = os.environ.get("GITHUB_API_URL") or "https://api.github.com"
    return GitHubApi(tok, repo, api)


def run_secrets_pipeline(ctx: RuntimeContext) -> str:
    s = ctx.settings
    if not s.secrets_reviewer.enabled:
        ctx.state["secrets_reviewer"] = {"executed": True, "skipped": True, "issue_urls": []}
        return json.dumps(ctx.state["secrets_reviewer"], indent=2)
    repo = ctx.repo_path
    sr = s.secrets_reviewer
    tmp = Path(tempfile.mkdtemp(prefix="appsec-crew-"))
    report = tmp / "betterleaks.json"
    cfg = Path(sr.betterleaks_config_path) if sr.betterleaks_config_path else None
    findings = run_betterleaks_scan(repo, sr.betterleaks_binary, cfg, report)
    gh = _github_client(s)
    issue_urls: list[str] = []
    for f in findings:
        rid = f.get("RuleID") or f.get("rule_id") or "unknown-rule"
        path = f.get("File") or f.get("file") or "?"
        line = f.get("StartLine") or f.get("line") or "?"
        title = f"[AppSec] Secret finding: {rid}"
        body = (
            "Automated report from **AppSec Crew** (Betterleaks).\n\n"
            f"- **Rule**: `{rid}`\n"
            f"- **Location**: `{path}` line {line}\n"
            "- Secret value is **not** included in this issue.\n"
            "- Ignore paths / allowlists: configure `.betterleaks.toml` / `.gitleaks.toml` in this repository.\n"
        )
        if gh:
            iss = gh.create_issue(title, body, labels=["security", "appsec-crew"])
            issue_urls.append(iss.get("html_url", ""))
    ctx.state["secrets_reviewer"] = {
        "issue_urls": [u for u in issue_urls if u],
        "findings_total": len(findings),
        "executed": True,
    }
    return json.dumps(ctx.state["secrets_reviewer"], indent=2)


def run_dependencies_pipeline(ctx: RuntimeContext) -> str:
    s = ctx.settings
    if not s.dependencies_reviewer.enabled:
        ctx.state["dependencies_reviewer"] = {"executed": True, "skipped": True, "pr_url": None}
        return json.dumps(ctx.state["dependencies_reviewer"], indent=2)
    dr = s.dependencies_reviewer
    repo = ctx.repo_path
    min_lvl = s.min_severity()
    cvss_min = cvss_floor_for_min_severity(min_lvl)
    include_unknown = include_osv_vuln_without_cvss(min_lvl)

    tmp = Path(tempfile.mkdtemp(prefix="appsec-crew-"))
    report = tmp / "osv.json"
    cfg = Path(dr.osv_config_path) if dr.osv_config_path else (repo / "osv-scanner.toml")
    cfg_path = cfg if cfg.is_file() else None
    rows = run_osv_scan(repo, dr.osv_scanner_binary, cfg_path, report)
    rows = filter_osv_by_min_cvss(rows, cvss_min, max_cvss_score, include_unknown)
    ctx.state["dependencies_reviewer"] = {"vulnerable_rows": len(rows), "pr_url": None, "executed": True}

    if not rows:
        return json.dumps(ctx.state["dependencies_reviewer"], indent=2)

    gh = _github_client(s)
    if not gh:
        ctx.state["dependencies_reviewer"]["error"] = "No GitHub token/repo; skipped PR."
        return json.dumps(ctx.state["dependencies_reviewer"], indent=2)

    targets = discover_remediation_targets(repo)
    if not targets:
        ctx.state["dependencies_reviewer"]["note"] = (
            "OSV reported vulnerabilities but no supported remediation target (e.g. package-lock.json, pom.xml) was found."
        )
        return json.dumps(ctx.state["dependencies_reviewer"], indent=2)

    branch = f"appsec-crew/deps-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
    ensure_identity(repo, os.environ.get("GIT_COMMITTER_NAME", "appsec-crew"), os.environ.get("GIT_COMMITTER_EMAIL", "appsec-crew@users.noreply.github.com"))
    create_branch(repo, branch)

    for _hint, path in targets:
        if path.name == "package-lock.json":
            run_osv_fix_inplace(path, dr.osv_scanner_binary, cvss_min)
        elif path.name == "pom.xml":
            run_osv_fix_override_pom(path, dr.osv_scanner_binary, cvss_min)

    label = human_severity_label(min_lvl)
    if not commit_all(
        repo,
        f"chore(appsec): remediate OSV findings (min severity {label})\n\nOpened by AppSec Crew (OSV-Scanner fix).",
    ):
        ctx.state["dependencies_reviewer"]["note"] = "No file changes after osv-scanner fix."
        return json.dumps(ctx.state["dependencies_reviewer"], indent=2)

    push_with_token(repo, branch, gh.token, gh.owner + "/" + gh.repo, api_host=_git_remote_host())
    base = gh.get_default_branch()
    pr = gh.create_pull_request(
        title=f"chore(appsec): dependency remediation (OSV, min {label})",
        body=(
            f"This PR applies **OSV-Scanner** guided remediation (`fix`) for vulnerabilities at or above **{label}** "
            f"(CVSS ≥ {cvss_min} when a score exists).\n\n"
            "Ignored IDs / packages: configure `osv-scanner.toml` in this repository.\n\n"
            "Review lockfile and POM changes carefully before merging."
        ),
        head=branch,
        base=base,
    )
    ctx.state["dependencies_reviewer"]["pr_url"] = pr.get("html_url")
    return json.dumps(ctx.state["dependencies_reviewer"], indent=2)


def run_code_pipeline(ctx: RuntimeContext) -> str:
    s = ctx.settings
    if not s.code_reviewer.enabled:
        ctx.state["code_reviewer"] = {"executed": True, "skipped": True, "pr_url": None}
        return json.dumps(ctx.state["code_reviewer"], indent=2)
    cr = s.code_reviewer
    repo = ctx.repo_path
    min_lvl = s.min_severity()
    lang = detect_primary_language(repo)
    cfg_path = Path(cr.semgrep_config_path) if cr.semgrep_config_path else None
    config_args = build_semgrep_config_args(repo, cfg_path, cr.semgrep_extra_configs)
    tmp = Path(tempfile.mkdtemp(prefix="appsec-crew-"))
    report = tmp / "semgrep.json"
    findings = run_semgrep(repo, cr.semgrep_binary, config_args, report, autofix=False)
    findings = filter_semgrep_by_min_severity(findings, min_lvl)
    ctx.state["code_reviewer"] = {
        "primary_language": lang,
        "findings": len(findings),
        "pr_url": None,
        "executed": True,
    }

    if not findings:
        return json.dumps(ctx.state["code_reviewer"], indent=2)

    gh = _github_client(s)
    if not gh:
        ctx.state["code_reviewer"]["error"] = "No GitHub token/repo; skipped PR."
        return json.dumps(ctx.state["code_reviewer"], indent=2)

    branch = f"appsec-crew/semgrep-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
    ensure_identity(repo, os.environ.get("GIT_COMMITTER_NAME", "appsec-crew"), os.environ.get("GIT_COMMITTER_EMAIL", "appsec-crew@users.noreply.github.com"))
    create_branch(repo, branch)
    run_semgrep(repo, cr.semgrep_binary, config_args, tmp / "semgrep-autofix.json", autofix=True)

    reasons = "\n".join(
        f"- `{f.get('check_id')}` @ `{f.get('path')}` — {((f.get('extra') or {}).get('message') or '')[:200]}"
        for f in findings[:40]
    )
    if len(findings) > 40:
        reasons += f"\n- … and {len(findings) - 40} more."

    label = human_severity_label(min_lvl)
    if not commit_all(
        repo,
        f"fix(appsec): Semgrep autofix (min severity {label})\n\nOpened by AppSec Crew.",
    ):
        ctx.state["code_reviewer"]["note"] = "Semgrep did not produce writable autofixes."
        return json.dumps(ctx.state["code_reviewer"], indent=2)

    push_with_token(repo, branch, gh.token, gh.owner + "/" + gh.repo, api_host=_git_remote_host())
    base = gh.get_default_branch()
    pr = gh.create_pull_request(
        title=f"fix(appsec): Semgrep autofix (min {label})",
        body=(
            f"Primary detected language: **{lang}**.\n\n"
            f"Minimum severity filter: **{label}** (configure `global.min_severity` in `appsec_crew.yaml`).\n\n"
            "### Findings addressed (sample)\n"
            f"{reasons}\n\n"
            "Rule ignores and paths: use `.semgrep.yml` in this repository.\n\n"
            "Changes were generated with `semgrep scan --autofix`. Please review."
        ),
        head=branch,
        base=base,
    )
    ctx.state["code_reviewer"]["pr_url"] = pr.get("html_url")
    return json.dumps(ctx.state["code_reviewer"], indent=2)


def _markdown_report(ctx: RuntimeContext) -> str:
    repo = os.environ.get("GITHUB_REPOSITORY") or "unknown/repo"
    min_s = ctx.settings.min_severity().upper()
    lines = [
        "## AppSec Crew summary",
        "",
        f"- **Repository**: `{repo}`",
        f"- **Minimum severity (global)**: **{min_s}**",
        f"- **UTC time**: {datetime.now(timezone.utc).isoformat()}",
        "",
        "### secrets-reviewer",
        "",
    ]
    sr = ctx.state.get("secrets_reviewer") or {}
    lines.append(f"- Issues: {len(sr.get('issue_urls') or [])} (findings considered: {sr.get('findings_total', 'n/a')})")
    for u in sr.get("issue_urls") or []:
        lines.append(f"  - {u}")
    lines += ["", "### dependencies-reviewer", ""]
    dr = ctx.state.get("dependencies_reviewer") or {}
    lines.append(f"- Vulnerable dependency rows: {dr.get('vulnerable_rows', 'n/a')}")
    if dr.get("pr_url"):
        lines.append(f"- PR: {dr['pr_url']}")
    lines += ["", "### code-reviewer", ""]
    cr = ctx.state.get("code_reviewer") or {}
    lines.append(f"- Primary language: `{cr.get('primary_language', '?')}`")
    lines.append(f"- Semgrep findings (after min severity): {cr.get('findings', 'n/a')}")
    if cr.get("pr_url"):
        lines.append(f"- PR: {cr['pr_url']}")
    return "\n".join(lines)


def run_reporter_pipeline(ctx: RuntimeContext) -> str:
    s = ctx.settings
    if not s.reporter.enabled:
        ctx.state["reporter"] = {"executed": True, "skipped": True, "markdown": ""}
        return "reporter disabled"
    text = _markdown_report(ctx)
    ctx.state["reporter"] = {"markdown": text, "executed": True}

    gh = _github_client(s)
    if gh and ctx.pr_number:
        gh.create_pr_comment(ctx.pr_number, text)

    repo_name = os.environ.get("GITHUB_REPOSITORY") or "unknown"
    rep = s.reporter
    jira_key = ""
    if rep.jira.enabled and rep.jira.base_url and rep.jira.project_key and rep.jira.email and rep.jira.api_token:
        client = JiraApi(rep.jira.base_url, rep.jira.email, rep.jira.api_token)
        jira_key = upsert_appsec_ticket(
            client,
            rep.jira.project_key,
            repo_name,
            text,
            rep.jira.issue_type,
        )
    ctx.state["reporter"]["jira_ticket"] = jira_key

    payload = {
        "date": datetime.now(timezone.utc).isoformat(),
        "repo": repo_name,
        "results": {
            "secrets-reviewer": (ctx.state.get("secrets_reviewer") or {}).get("issue_urls") or [],
            "dependencies-reviewer": [((ctx.state.get("dependencies_reviewer") or {}).get("pr_url") or "")]
            if (ctx.state.get("dependencies_reviewer") or {}).get("pr_url")
            else [],
            "code-reviewer": [((ctx.state.get("code_reviewer") or {}).get("pr_url") or "")]
            if (ctx.state.get("code_reviewer") or {}).get("pr_url")
            else [],
        },
        "jira_ticket": jira_key,
    }
    payload["results"]["dependencies-reviewer"] = [x for x in payload["results"]["dependencies-reviewer"] if x]
    payload["results"]["code-reviewer"] = [x for x in payload["results"]["code-reviewer"] if x]

    if rep.webhook.enabled and rep.webhook.url:
        headers = dict(rep.webhook.headers)
        for hk, ev in (rep.webhook.header_secrets or {}).items():
            val = os.environ.get(ev)
            if val:
                headers[hk] = val
        post_json(rep.webhook.url, payload, headers=headers or None)

    if rep.splunk.enabled and rep.splunk.hec_url and rep.splunk.token:
        send_event(rep.splunk.hec_url, rep.splunk.token, payload, rep.splunk.source, rep.splunk.sourcetype)

    ctx.state["reporter"]["webhook_payload"] = payload
    return text


def validate_postconditions(ctx: RuntimeContext) -> list[str]:
    errs: list[str] = []
    s = ctx.settings
    for name, enabled in (
        ("secrets_reviewer", s.secrets_reviewer.enabled),
        ("dependencies_reviewer", s.dependencies_reviewer.enabled),
        ("code_reviewer", s.code_reviewer.enabled),
        ("reporter", s.reporter.enabled),
    ):
        if not enabled:
            continue
        st = ctx.state.get(name)
        if not st or not st.get("executed"):
            errs.append(f"Enabled agent '{name}' did not record execution in state.")
    return errs
