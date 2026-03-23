"""Local git helpers for opening fix pull requests."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path


def run_git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=str(repo),
        check=check,
        text=True,
        capture_output=True,
        env={**os.environ},
    )


def ensure_identity(repo: Path, name: str, email: str) -> None:
    run_git(repo, "config", "user.name", name)
    run_git(repo, "config", "user.email", email)


def has_changes(repo: Path) -> bool:
    p = run_git(repo, "status", "--porcelain")
    return bool(p.stdout.strip())


def create_branch(repo: Path, branch: str) -> None:
    run_git(repo, "checkout", "-b", branch)


def commit_all(repo: Path, message: str) -> bool:
    if not has_changes(repo):
        return False
    run_git(repo, "add", "-A")
    run_git(repo, "commit", "-m", message)
    return True


def push_with_token(repo: Path, branch: str, token: str, owner_repo: str, api_host: str = "github.com") -> None:
    """Push `branch` to origin using HTTPS token (GitHub Actions friendly)."""
    url = f"https://x-access-token:{token}@{api_host}/{owner_repo}.git"
    run_git(repo, "remote", "set-url", "origin", url)
    run_git(repo, "push", "-u", "origin", branch)
