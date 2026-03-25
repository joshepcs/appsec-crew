"""Git ref to clone ``celagus/appsec-crew`` in the reusable Actions workflow bootstrap.

The bash step **Resolve celagus/appsec-crew ref** in ``.github/workflows/appsec-crew-reusable.yml`` must
implement the same rules (``pull_request`` yields ``refs/pull/N/merge``, which does not exist on crew).
"""

from __future__ import annotations


def resolve_celagus_appsec_crew_checkout_ref(workflow_ref: str, workflow_sha: str) -> str:
    """
    Mirror ``github.workflow_ref`` / ``github.workflow_sha`` in a ``workflow_call`` job.

    ``workflow_ref`` is typically ``owner/repo/.github/workflows/<file>.yml@<git-ref>``.
    """
    wf_ref = (workflow_ref or "").strip()
    wf_sha = (workflow_sha or "").strip()

    # Bash: ref="${wf_ref#*@}"
    if "@" in wf_ref:
        ref = wf_ref.split("@", 1)[1]
    else:
        ref = wf_ref

    # Bash: case refs/pull/*|"") ref="$workflow_sha" ;; esac
    if not ref or ref.startswith("refs/pull/"):
        ref = wf_sha

    if not ref:
        msg = "Could not resolve ref for celagus/appsec-crew checkout"
        raise ValueError(msg)
    return ref
