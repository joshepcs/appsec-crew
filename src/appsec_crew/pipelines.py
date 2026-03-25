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
from appsec_crew.scanners.osv_scan import run_osv_scan
from appsec_crew.scanners.semgrep_scan import build_semgrep_config_args, detect_primary_language, run_semgrep
from appsec_crew.triage_llm import llm_triage_batch, partition_by_dismiss_indices
from appsec_crew.settings import (
    AppSecSettings,
    CodeReviewerSettings,
    DependenciesReviewerSettings,
    SecretsReviewerSettings,
)
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


def _is_pr_scan_mode(ctx: RuntimeContext) -> bool:
    """
    True for ``pull_request`` / ``pull_request_target`` with a resolved PR number.

    In this mode we only annotate the **current PR** (summary comment + optional inline Semgrep review);
    we do **not** open GitHub Issues or AppSec-owned remediation PRs.
    """
    name = (ctx.github_event_name or os.environ.get("GITHUB_EVENT_NAME") or "").strip()
    if name not in ("pull_request", "pull_request_target"):
        return False
    return ctx.pr_number is not None


def _format_osv_rows_for_issue(rows: list[dict[str, Any]], cvss_min: float, label: str) -> str:
    lines: list[str] = [
        f"Automated **OSV-Scanner** report from AppSec Crew (minimum severity **{label}**, "
        f"CVSS floor **{cvss_min}** when scored).\n",
        "Ignored packages / IDs: configure `osv-scanner.toml` in this repository.\n",
        "### Vulnerable package rows\n",
    ]
    for row in rows[:100]:
        pkg = row.get("package") if isinstance(row.get("package"), dict) else {}
        name = pkg.get("name") or "?"
        eco = pkg.get("ecosystem") or "?"
        vulns = [v for v in (row.get("vulnerabilities") or []) if isinstance(v, dict)][:20]
        vids = [str(v.get("id") or "?") for v in vulns]
        lines.append(f"- **{name}** (`{eco}`): {', '.join(vids) if vids else '(no id)'}")
    if len(rows) > 100:
        lines.append(f"\n… and **{len(rows) - 100}** more row(s).")
    return "\n".join(lines)


def _semgrep_finding_line(finding: dict[str, Any]) -> int | None:
    start = finding.get("start")
    if isinstance(start, dict):
        line = start.get("line")
        if isinstance(line, int) and line > 0:
            return line
    return None


def _post_semgrep_pr_review(
    gh: GitHubApi,
    pr_number: int,
    findings: list[dict[str, Any]],
) -> str | None:
    """Post a PR review with inline comments where possible; fall back to issue comment. Returns review URL or None."""
    try:
        pr_data = gh.get_pull_request(pr_number)
        commit_id = (pr_data.get("head") or {}).get("sha")
        if not commit_id:
            return None
    except Exception:
        return None

    max_inline = 25
    comments: list[dict[str, Any]] = []
    for f in findings[:max_inline]:
        path = f.get("path")
        line = _semgrep_finding_line(f)
        if not path or line is None:
            continue
        chk = f.get("check_id") or "?"
        msg = ((f.get("extra") or {}).get("message") or "")[:400]
        comments.append(
            {
                "path": str(path),
                "line": line,
                "body": (f"**Semgrep** `{chk}`\n\n{msg}" if msg else f"**Semgrep** `{chk}`"),
            }
        )

    body = (
        "### AppSec Crew — Semgrep\n\n"
        f"**Findings** (after severity filter + triage): **{len(findings)}**\n\n"
        f"Inline comments below: **{len(comments)}** (capped at {max_inline}; lines must be part of this PR diff).\n"
    )
    try:
        if comments:
            review = gh.create_pull_request_review(
                pr_number, commit_id=str(commit_id), body=body, comments=comments
            )
        else:
            listing = "\n".join(
                f"- `{f.get('check_id')}` @ `{f.get('path')}`"
                + (f":{_semgrep_finding_line(f)}" if _semgrep_finding_line(f) else "")
                for f in findings[:50]
            )
            review = gh.create_pull_request_review(
                pr_number,
                commit_id=str(commit_id),
                body=body + "\n### Findings\n\n" + listing,
                comments=None,
            )
        url = review.get("html_url")
        return str(url) if url else None
    except Exception:
        try:
            listing = "\n".join(
                f"- `{f.get('check_id')}` @ `{f.get('path')}`"
                for f in findings[:50]
            )
            gh.create_pr_comment(pr_number, body + "\n### Findings\n\n" + listing)
        except Exception:
            pass
        return None


def _github_output_urls(agent: dict[str, Any]) -> list[str]:
    """Collect non-empty GitHub URLs from agent state (issues, PRs, PR reviews)."""
    out: list[str] = []
    for u in agent.get("issue_urls") or []:
        if u:
            out.append(str(u))
    for key in ("pr_url", "semgrep_review_url"):
        v = agent.get(key)
        if v:
            out.append(str(v))
    return out


def _triage_secrets_findings(
    sr: SecretsReviewerSettings, findings: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if not findings or not sr.llm_triage_findings or not sr.llm.api_key:
        return findings, []
    items = []
    for i, f in enumerate(findings):
        rid = f.get("RuleID") or f.get("rule_id") or "?"
        path = f.get("File") or f.get("file") or "?"
        line = f.get("StartLine") or f.get("line") or "?"
        items.append({"index": i, "rule_id": rid, "path": str(path), "line": line})
    guidance = (
        "Dismiss likely false positives: mocks/examples/placeholders, test fixtures, sample `.env` in docs, "
        "strings clearly labeled fake, or paths that cannot hold production secrets."
    )
    meta = llm_triage_batch(
        sr.llm,
        agent_role="secrets reviewer",
        items=items,
        guidance=guidance,
    )
    return partition_by_dismiss_indices(findings, meta)


def _triage_osv_rows(
    dr: DependenciesReviewerSettings, rows: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if not rows or not dr.llm_triage_findings or not dr.llm.api_key:
        return rows, []
    items = []
    for i, row in enumerate(rows):
        pkg = row.get("package") if isinstance(row.get("package"), dict) else {}
        vulns = [v for v in (row.get("vulnerabilities") or []) if isinstance(v, dict)][:10]
        vid = [str(v.get("id") or "?") for v in vulns]
        items.append(
            {
                "index": i,
                "package": pkg.get("name"),
                "ecosystem": pkg.get("ecosystem"),
                "vuln_ids": vid,
            }
        )
    guidance = (
        "Dismiss likely false positives: dependency not reachable from shipped code, dev-only tooling with no prod path, "
        "duplicate advisory rows, or package versions not actually built into the artifact."
    )
    meta = llm_triage_batch(
        dr.llm,
        agent_role="dependency vulnerability reviewer",
        items=items,
        guidance=guidance,
    )
    return partition_by_dismiss_indices(rows, meta)


def _triage_semgrep_findings(
    cr: CodeReviewerSettings, findings: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if not findings or not cr.llm_triage_findings or not cr.llm.api_key:
        return findings, []
    items = []
    for i, f in enumerate(findings):
        extra = f.get("extra") if isinstance(f.get("extra"), dict) else {}
        items.append(
            {
                "index": i,
                "check_id": f.get("check_id"),
                "path": f.get("path"),
                "message": str(extra.get("message") or "")[:450],
            }
        )
    guidance = (
        "Dismiss likely false positives: test-only code, dead branches, benign patterns, framework boilerplate, "
        "or findings inconsistent with how the application actually uses the flagged code."
    )
    meta = llm_triage_batch(
        cr.llm,
        agent_role="static analysis reviewer",
        items=items,
        guidance=guidance,
    )
    return partition_by_dismiss_indices(findings, meta)


def _public_secret_dismissals(dismissed: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for d in dismissed:
        out.append(
            {
                "rule_id": d.get("RuleID") or d.get("rule_id"),
                "path": d.get("File") or d.get("file"),
                "line": d.get("StartLine") or d.get("line"),
                "reason": d.get("_dismiss_reason"),
            }
        )
    return out


def _public_osv_dismissals(dismissed: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for d in dismissed:
        pkg = d.get("package") if isinstance(d.get("package"), dict) else {}
        out.append(
            {
                "package": pkg.get("name"),
                "ecosystem": pkg.get("ecosystem"),
                "reason": d.get("_dismiss_reason"),
            }
        )
    return out


def _public_semgrep_dismissals(dismissed: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for d in dismissed:
        out.append(
            {
                "check_id": d.get("check_id"),
                "path": d.get("path"),
                "reason": d.get("_dismiss_reason"),
            }
        )
    return out


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
    commands: list[str] = []
    raw_findings = run_betterleaks_scan(
        repo,
        sr.betterleaks_binary,
        cfg,
        report,
        extra_args=sr.betterleaks_extra_args,
        command_template=sr.betterleaks_command,
        commands_log=commands,
    )
    scanner_total = len(raw_findings)
    findings, dismissed_raw = _triage_secrets_findings(sr, raw_findings)
    dismissed_pub = _public_secret_dismissals(dismissed_raw)
    gh = _github_client(s)
    issue_urls: list[str] = []
    pr_mode = _is_pr_scan_mode(ctx)
    if gh and findings and not pr_mode:
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
            iss = gh.create_issue(title, body, labels=["security", "appsec-crew"])
            issue_urls.append(iss.get("html_url", ""))
    ctx.state["secrets_reviewer"] = {
        "commands_executed": commands,
        "issue_urls": [u for u in issue_urls if u],
        "pr_scan_mode": pr_mode,
        "scanner_findings_total": scanner_total,
        "findings_after_triage": len(findings),
        "dismissed_findings": dismissed_pub,
        "findings_total": len(findings),
        "executed": True,
    }
    return json.dumps(ctx.state["secrets_reviewer"], indent=2)


def run_dependencies_pipeline(ctx: RuntimeContext) -> str:
    s = ctx.settings
    if not s.dependencies_reviewer.enabled:
        ctx.state["dependencies_reviewer"] = {
            "executed": True,
            "skipped": True,
            "pr_url": None,
            "issue_urls": [],
        }
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
    commands: list[str] = []
    rows = run_osv_scan(
        repo,
        dr.osv_scanner_binary,
        cfg_path,
        report,
        extra_args=dr.osv_scan_extra_args,
        command_template=dr.osv_scan_command,
        commands_log=commands,
    )
    rows = filter_osv_by_min_cvss(rows, cvss_min, max_cvss_score, include_unknown)
    after_cvss = len(rows)
    rows, dismissed_raw = _triage_osv_rows(dr, rows)
    dismissed_pub = _public_osv_dismissals(dismissed_raw)
    ctx.state["dependencies_reviewer"] = {
        "vulnerable_rows": len(rows),
        "scanner_rows_after_cvss": after_cvss,
        "dismissed_findings": dismissed_pub,
        "commands_executed": commands,
        "pr_url": None,
        "issue_urls": [],
        "executed": True,
    }

    if not rows:
        return json.dumps(ctx.state["dependencies_reviewer"], indent=2)

    gh = _github_client(s)
    if not gh:
        ctx.state["dependencies_reviewer"]["error"] = "No GitHub token/repo; skipped GitHub output."
        return json.dumps(ctx.state["dependencies_reviewer"], indent=2)

    if _is_pr_scan_mode(ctx):
        ctx.state["dependencies_reviewer"]["note"] = (
            "PR scan mode: dependency findings are only in the PR summary comment (no GitHub Issue)."
        )
        return json.dumps(ctx.state["dependencies_reviewer"], indent=2)

    label = human_severity_label(min_lvl)
    title = f"[AppSec] OSV-Scanner: {len(rows)} vulnerable package row(s) (min {label})"
    body = _format_osv_rows_for_issue(rows, cvss_min, label)
    iss = gh.create_issue(title, body, labels=["security", "appsec-crew", "dependencies"])
    url = iss.get("html_url", "")
    ctx.state["dependencies_reviewer"]["issue_urls"] = [u for u in [url] if u]
    return json.dumps(ctx.state["dependencies_reviewer"], indent=2)


def run_code_pipeline(ctx: RuntimeContext) -> str:
    s = ctx.settings
    if not s.code_reviewer.enabled:
        ctx.state["code_reviewer"] = {
            "executed": True,
            "skipped": True,
            "pr_url": None,
            "issue_urls": [],
            "semgrep_review_url": None,
        }
        return json.dumps(ctx.state["code_reviewer"], indent=2)
    cr = s.code_reviewer
    repo = ctx.repo_path
    min_lvl = s.min_severity()
    lang = detect_primary_language(repo)
    cfg_path = Path(cr.semgrep_config_path) if cr.semgrep_config_path else None
    config_args = build_semgrep_config_args(repo, cfg_path, cr.semgrep_extra_configs)
    tmp = Path(tempfile.mkdtemp(prefix="appsec-crew-"))
    report = tmp / "semgrep.json"
    commands: list[str] = []
    findings = run_semgrep(
        repo,
        cr.semgrep_binary,
        config_args,
        report,
        autofix=False,
        extra_args=cr.semgrep_extra_args,
        command_template=cr.semgrep_command,
        commands_log=commands,
    )
    before_min_severity = len(findings)
    findings = filter_semgrep_by_min_severity(findings, min_lvl)
    after_filter = len(findings)
    findings, dismissed_raw = _triage_semgrep_findings(cr, findings)
    dismissed_pub = _public_semgrep_dismissals(dismissed_raw)
    ctx.state["code_reviewer"] = {
        "primary_language": lang,
        "findings": len(findings),
        "semgrep_findings_before_min_severity": before_min_severity,
        "scanner_findings_after_severity": after_filter,
        "dismissed_findings": dismissed_pub,
        "commands_executed": commands,
        "pr_url": None,
        "issue_urls": [],
        "semgrep_review_url": None,
        "executed": True,
    }

    if not findings:
        return json.dumps(ctx.state["code_reviewer"], indent=2)

    gh = _github_client(s)
    if not gh:
        ctx.state["code_reviewer"]["error"] = "No GitHub token/repo; skipped GitHub output."
        return json.dumps(ctx.state["code_reviewer"], indent=2)

    label = human_severity_label(min_lvl)
    reasons = "\n".join(
        f"- `{f.get('check_id')}` @ `{f.get('path')}` — {((f.get('extra') or {}).get('message') or '')[:200]}"
        for f in findings[:40]
    )
    if len(findings) > 40:
        reasons += f"\n- … and {len(findings) - 40} more."

    if _is_pr_scan_mode(ctx) and ctx.pr_number is not None:
        review_url = _post_semgrep_pr_review(gh, ctx.pr_number, findings)
        ctx.state["code_reviewer"]["semgrep_review_url"] = review_url
        ctx.state["code_reviewer"]["pr_scan_mode"] = True
        ctx.state["code_reviewer"]["note"] = (
            "PR scan mode: Semgrep posted as PR review / comment (no autofix branch or Issues)."
        )
        return json.dumps(ctx.state["code_reviewer"], indent=2)

    ctx.state["code_reviewer"]["pr_scan_mode"] = False
    branch = f"appsec-crew/semgrep-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
    ensure_identity(
        repo,
        os.environ.get("GIT_COMMITTER_NAME", "appsec-crew"),
        os.environ.get("GIT_COMMITTER_EMAIL", "appsec-crew@users.noreply.github.com"),
    )
    create_branch(repo, branch)
    run_semgrep(
        repo,
        cr.semgrep_binary,
        config_args,
        tmp / "semgrep-autofix.json",
        autofix=True,
        extra_args=cr.semgrep_extra_args,
        command_template=cr.semgrep_command,
        commands_log=commands,
    )

    if not commit_all(
        repo,
        f"fix(appsec): Semgrep autofix (min severity {label})\n\nOpened by AppSec Crew.",
    ):
        title = f"[AppSec] Semgrep: {len(findings)} finding(s), no autofix (min {label})"
        body = (
            "Scheduled **AppSec Crew** run: Semgrep reported findings but **no writable autofix** was produced "
            "(rules may not support `--autofix`, or edits did not change tracked files).\n\n"
            f"Primary language: **{lang}**. Minimum severity: **{label}**.\n\n"
            "### Findings (sample)\n"
            f"{reasons}\n\n"
            "Configure ignores in `.semgrep.yml` and severity via `global.min_severity` in `appsec_crew.yaml`.\n"
        )
        iss = gh.create_issue(title, body, labels=["security", "appsec-crew", "semgrep"])
        url = iss.get("html_url", "")
        ctx.state["code_reviewer"]["issue_urls"] = [u for u in [url] if u]
        ctx.state["code_reviewer"]["note"] = (
            "Semgrep did not produce writable autofixes; opened a tracking GitHub Issue."
        )
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
    pr_scan = _is_pr_scan_mode(ctx)
    run_mode = (
        "**PR** — summary on this PR only (no Issues; Semgrep as PR review when possible)."
        if pr_scan
        else "**Batch / scheduled** — Issues for secrets & OSV; Semgrep autofix PR or a tracking Issue."
    )
    lines = [
        "## AppSec Crew summary",
        "",
        f"- **Repository**: `{repo}`",
        f"- **Run mode**: {run_mode}",
        f"- **Minimum severity (global)**: **{min_s}**",
        f"- **UTC time**: {datetime.now(timezone.utc).isoformat()}",
        "",
        "- **Tool versions (config)**: "
        f"Betterleaks `{ctx.settings.tool_versions.betterleaks}`, "
        f"OSV-Scanner `{ctx.settings.tool_versions.osv_scanner}`, "
        f"Semgrep `{ctx.settings.tool_versions.semgrep}`",
        "",
        "Scans target the **checked-out repository workspace** recursively by default "
        "(Betterleaks `dir` over the tree, OSV `-r`, Semgrep `scan` on the repo root).",
        "",
        "### secrets-reviewer",
        "",
    ]
    sr = ctx.state.get("secrets_reviewer") or {}
    if sr.get("pr_scan_mode"):
        lines.append(
            "- **PR scan mode**: Betterleaks is summarized here only (**no** GitHub Issues opened)."
        )
    lines.append(
        f"- Issues opened: {len(sr.get('issue_urls') or [])} "
        f"(after triage: **{sr.get('findings_after_triage', sr.get('findings_total', 'n/a'))}** actionable; "
        f"scanner raw: **{sr.get('scanner_findings_total', 'n/a')}**)"
    )
    for u in sr.get("issue_urls") or []:
        lines.append(f"  - {u}")
    cmds = sr.get("commands_executed") or []
    if cmds:
        lines.append("- **Tool commands executed:**")
        for c in cmds:
            lines.append(f"  - `{c}`")
    dis = sr.get("dismissed_findings") or []
    if dis:
        lines.append(f"- **Dismissed as likely false positives ({len(dis)}):**")
        for d in dis[:30]:
            lines.append(f"  - {d}")
        if len(dis) > 30:
            lines.append(f"  - … and {len(dis) - 30} more")

    lines += ["", "### dependencies-reviewer", ""]
    dr = ctx.state.get("dependencies_reviewer") or {}
    lines.append(
        f"- Vulnerable dependency rows (after CVSS filter + triage): **{dr.get('vulnerable_rows', 'n/a')}** "
        f"(pre-triage post-filter: **{dr.get('scanner_rows_after_cvss', 'n/a')}**)"
    )
    if dr.get("note"):
        lines.append(f"- Note: {dr['note']}")
    diu = dr.get("issue_urls") or []
    if diu:
        lines.append(f"- **GitHub Issues**: {len(diu)}")
        for u in diu:
            lines.append(f"  - {u}")
    if dr.get("pr_url"):
        lines.append(f"- PR: {dr['pr_url']}")
    dcmds = dr.get("commands_executed") or []
    if dcmds:
        lines.append("- **Tool commands executed:**")
        for c in dcmds:
            lines.append(f"  - `{c}`")
    ddis = dr.get("dismissed_findings") or []
    if ddis:
        lines.append(f"- **Dismissed dependency rows ({len(ddis)}):**")
        for d in ddis[:25]:
            lines.append(f"  - {d}")

    lines += ["", "### code-reviewer", ""]
    cr = ctx.state.get("code_reviewer") or {}
    lines.append(f"- Primary language: `{cr.get('primary_language', '?')}`")
    lines.append(
        f"- Semgrep findings (after min severity + triage): **{cr.get('findings', 'n/a')}** "
        f"(after severity filter, pre-triage: **{cr.get('scanner_findings_after_severity', 'n/a')}**; "
        f"raw from scan: **{cr.get('semgrep_findings_before_min_severity', 'n/a')}**)"
    )
    if cr.get("pr_scan_mode"):
        lines.append(
            "- **PR scan mode**: Semgrep as PR review / comment (**no** autofix branch or Issue from this run)."
        )
    if cr.get("semgrep_review_url"):
        lines.append(f"- **Semgrep PR review**: {cr['semgrep_review_url']}")
    ciu = cr.get("issue_urls") or []
    if ciu:
        lines.append(f"- **GitHub Issues**: {len(ciu)}")
        for u in ciu:
            lines.append(f"  - {u}")
    if cr.get("pr_url"):
        lines.append(f"- **Autofix PR**: {cr['pr_url']}")
    if cr.get("note") and not cr.get("pr_scan_mode"):
        lines.append(f"- Note: {cr['note']}")
    ccmds = cr.get("commands_executed") or []
    if ccmds:
        lines.append("- **Tool commands executed:**")
        for c in ccmds:
            lines.append(f"  - `{c}`")
    cdis = cr.get("dismissed_findings") or []
    if cdis:
        lines.append(f"- **Dismissed Semgrep findings ({len(cdis)}):**")
        for d in cdis[:25]:
            lines.append(f"  - {d}")
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

    sr_st = ctx.state.get("secrets_reviewer") or {}
    dr_st = ctx.state.get("dependencies_reviewer") or {}
    cr_st = ctx.state.get("code_reviewer") or {}
    payload = {
        "date": datetime.now(timezone.utc).isoformat(),
        "repo": repo_name,
        "results": {
            "secrets-reviewer": _github_output_urls(sr_st),
            "dependencies-reviewer": _github_output_urls(dr_st),
            "code-reviewer": _github_output_urls(cr_st),
        },
        "dismissed_counts": {
            "secrets-reviewer": len(sr_st.get("dismissed_findings") or []),
            "dependencies-reviewer": len(dr_st.get("dismissed_findings") or []),
            "code-reviewer": len(cr_st.get("dismissed_findings") or []),
        },
        "jira_ticket": jira_key,
    }

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
