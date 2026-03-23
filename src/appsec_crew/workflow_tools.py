"""CrewAI tools that invoke deterministic security pipelines."""

from __future__ import annotations

from crewai.tools import BaseTool

from appsec_crew.pipelines import (
    run_code_pipeline,
    run_dependencies_pipeline,
    run_reporter_pipeline,
    run_secrets_pipeline,
)
from appsec_crew.runtime import get_ctx


class SecretsReviewerTool(BaseTool):
    name: str = "secrets_reviewer_workflow"
    description: str = (
        "Runs Betterleaks on the repository, applies configured exceptions, "
        "and opens one GitHub issue per remaining secret finding. Call once."
    )

    def _run(self) -> str:
        return run_secrets_pipeline(get_ctx())


class DependenciesReviewerTool(BaseTool):
    name: str = "dependencies_reviewer_workflow"
    description: str = (
        "Runs OSV-Scanner, filters HIGH/CRITICAL (CVSS), applies osv-scanner fix where supported, "
        "and opens a single dependency remediation PR. Call once."
    )

    def _run(self) -> str:
        return run_dependencies_pipeline(get_ctx())


class CodeReviewerTool(BaseTool):
    name: str = "code_reviewer_workflow"
    description: str = (
        "Detects the dominant source language, runs Semgrep with repo + registry configs, "
        "filters HIGH/CRITICAL findings, applies Semgrep autofix, and opens a PR describing rationale. Call once."
    )

    def _run(self) -> str:
        return run_code_pipeline(get_ctx())


class ReporterTool(BaseTool):
    name: str = "reporter_workflow"
    description: str = (
        "Summarizes prior workflows, optionally comments on the current PR, "
        "upserts the Jira tracking ticket, POSTs the webhook JSON, and sends Splunk HEC. Call once."
    )

    def _run(self) -> str:
        return run_reporter_pipeline(get_ctx())
