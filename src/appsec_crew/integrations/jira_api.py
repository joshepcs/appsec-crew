"""Jira Cloud REST: find-or-create issue by exact summary."""

from __future__ import annotations

from typing import Any

import httpx


class JiraApi:
    def __init__(self, base_url: str, email: str, api_token: str) -> None:
        self.base = base_url.rstrip("/")
        self.auth = (email, api_token)

    def find_issue_by_exact_summary(self, project_key: str, summary_exact: str) -> str | None:
        jql = f'project = {project_key} AND summary ~ "AppSec crew findings"'
        r = httpx.get(
            f"{self.base}/rest/api/3/search",
            auth=self.auth,
            params={"jql": jql, "maxResults": 25, "fields": "summary,key"},
            timeout=60.0,
        )
        r.raise_for_status()
        for issue in r.json().get("issues") or []:
            fields = issue.get("fields") or {}
            if fields.get("summary") == summary_exact:
                return str(issue.get("key"))
        return None

    def create_issue(
        self,
        project_key: str,
        summary: str,
        description_md: str,
        issue_type: str,
    ) -> str:
        payload = {
            "fields": {
                "project": {"key": project_key},
                "summary": summary[:254],
                "description": {
                    "type": "doc",
                    "version": 1,
                    "content": [
                        {
                            "type": "paragraph",
                            "content": [{"type": "text", "text": description_md[:32000]}],
                        }
                    ],
                },
                "issuetype": {"name": issue_type},
            }
        }
        r = httpx.post(
            f"{self.base}/rest/api/3/issue",
            auth=self.auth,
            json=payload,
            timeout=60.0,
        )
        r.raise_for_status()
        return str(r.json().get("key"))

    def update_description(self, issue_key: str, description_md: str) -> None:
        payload = {
            "fields": {
                "description": {
                    "type": "doc",
                    "version": 1,
                    "content": [
                        {
                            "type": "paragraph",
                            "content": [{"type": "text", "text": description_md[:32000]}],
                        }
                    ],
                }
            }
        }
        r = httpx.put(
            f"{self.base}/rest/api/3/issue/{issue_key}",
            auth=self.auth,
            json=payload,
            timeout=60.0,
        )
        r.raise_for_status()


def upsert_appsec_ticket(
    client: JiraApi,
    project_key: str,
    repo_name: str,
    body_md: str,
    issue_type: str,
) -> str:
    summary = f"[AppSec crew findings: {repo_name}]"
    existing = client.find_issue_by_exact_summary(project_key, summary)
    if existing:
        client.update_description(existing, body_md)
        return existing
    return client.create_issue(project_key, summary, body_md, issue_type)
