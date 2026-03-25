"""Minimal GitHub REST v3 client for issues and pull requests."""

from __future__ import annotations

from typing import Any

import httpx


class GitHubApi:
    def __init__(self, token: str, repository: str, api_url: str | None = None) -> None:
        self.token = token
        self.owner, self.repo = repository.split("/", 1)
        self.api_url = (api_url or "https://api.github.com").rstrip("/")
        self._headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    def _url(self, path: str) -> str:
        return f"{self.api_url}{path}"

    def get_default_branch(self) -> str:
        r = httpx.get(
            self._url(f"/repos/{self.owner}/{self.repo}"),
            headers=self._headers,
            timeout=60.0,
        )
        r.raise_for_status()
        return str(r.json().get("default_branch") or "main")

    def create_issue(self, title: str, body: str, labels: list[str] | None = None) -> dict[str, Any]:
        payload: dict[str, Any] = {"title": title, "body": body}
        if labels:
            payload["labels"] = labels
        r = httpx.post(
            self._url(f"/repos/{self.owner}/{self.repo}/issues"),
            headers=self._headers,
            json=payload,
            timeout=60.0,
        )
        r.raise_for_status()
        return r.json()

    def create_pull_request(
        self,
        title: str,
        body: str,
        head: str,
        base: str,
    ) -> dict[str, Any]:
        payload = {"title": title, "body": body, "head": head, "base": base}
        r = httpx.post(
            self._url(f"/repos/{self.owner}/{self.repo}/pulls"),
            headers=self._headers,
            json=payload,
            timeout=60.0,
        )
        r.raise_for_status()
        return r.json()

    def create_pr_comment(self, pr_number: int, body: str) -> dict[str, Any]:
        r = httpx.post(
            self._url(f"/repos/{self.owner}/{self.repo}/issues/{pr_number}/comments"),
            headers=self._headers,
            json={"body": body},
            timeout=60.0,
        )
        r.raise_for_status()
        return r.json()

    def get_pull_request(self, pr_number: int) -> dict[str, Any]:
        r = httpx.get(
            self._url(f"/repos/{self.owner}/{self.repo}/pulls/{pr_number}"),
            headers=self._headers,
            timeout=60.0,
        )
        r.raise_for_status()
        return r.json()

    def create_pull_request_review(
        self,
        pr_number: int,
        *,
        commit_id: str,
        body: str,
        comments: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Submit a PR review (``event=COMMENT``). Optional inline ``comments``: ``path``, ``line``, ``body``."""
        payload: dict[str, Any] = {
            "commit_id": commit_id,
            "event": "COMMENT",
            "body": body,
        }
        if comments:
            payload["comments"] = comments
        r = httpx.post(
            self._url(f"/repos/{self.owner}/{self.repo}/pulls/{pr_number}/reviews"),
            headers=self._headers,
            json=payload,
            timeout=120.0,
        )
        r.raise_for_status()
        return r.json()
