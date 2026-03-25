"""Contract tests for reusable-workflow bootstrap ref (PR merge vs branch/tag)."""

from __future__ import annotations

import pytest

from appsec_crew.resolve_crew_checkout_ref import resolve_celagus_appsec_crew_checkout_ref


@pytest.mark.parametrize(
    ("workflow_ref", "workflow_sha", "expected"),
    [
        (
            "celagus/appsec-crew/.github/workflows/appsec-crew-reusable.yml@develop",
            "deadbeef",
            "develop",
        ),
        (
            "celagus/appsec-crew/.github/workflows/appsec-crew-reusable.yml@refs/heads/main",
            "abc123",
            "refs/heads/main",
        ),
        (
            "celagus/appsec-crew/.github/workflows/appsec-crew-reusable.yml@v1.0.0",
            "abc",
            "v1.0.0",
        ),
        (
            "celagus/appsec-crew/.github/workflows/appsec-crew-reusable.yml@a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",
            "unused",
            "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",
        ),
        # pull_request: merge ref exists only on caller — must use workflow_sha (commit on celagus/appsec-crew)
        (
            "celagus/appsec-crew/.github/workflows/appsec-crew-reusable.yml@refs/pull/163/merge",
            "9fceb1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8",
            "9fceb1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8",
        ),
        (
            "celagus/appsec-crew/.github/workflows/appsec-crew-reusable.yml@refs/pull/1/head",
            "sha-for-crew",
            "sha-for-crew",
        ),
        # Empty suffix after @ → workflow_sha
        (
            "celagus/appsec-crew/.github/workflows/appsec-crew-reusable.yml@",
            "fallbacksha",
            "fallbacksha",
        ),
    ],
)
def test_resolve_matches_github_actions_bootstrap(
    workflow_ref: str, workflow_sha: str, expected: str
) -> None:
    assert resolve_celagus_appsec_crew_checkout_ref(workflow_ref, workflow_sha) == expected


def test_resolve_raises_when_unresolvable() -> None:
    with pytest.raises(ValueError, match="Could not resolve"):
        resolve_celagus_appsec_crew_checkout_ref("pkg/.github/workflows/w.yml@", "")

    with pytest.raises(ValueError, match="Could not resolve"):
        resolve_celagus_appsec_crew_checkout_ref(
            "pkg/.github/workflows/w.yml@refs/pull/99/merge",
            "",
        )


def test_no_at_sign_uses_full_string_if_not_pull() -> None:
    """If workflow_ref had no ``@``, bash leaves ref as full string; same here."""
    assert resolve_celagus_appsec_crew_checkout_ref("refs/heads/feature", "sha") == "refs/heads/feature"
