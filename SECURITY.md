# Security policy

## Supported versions

Security updates are applied to the latest release line on the default branch. Pin your workflows to a tag or commit SHA rather than a moving branch when you need predictable behavior.

## Reporting a vulnerability

**Please do not open a public GitHub issue for security reports.**

Instead, use one of these options:

1. **GitHub private vulnerability reporting** — if enabled on this repository, use **Security → Report a vulnerability**.
2. **Maintainer contact** — reach out through the contact method listed on the organization or maintainer profile.

Include:

- A short description of the issue and its impact
- Steps to reproduce (or a proof-of-concept), if safe to share
- Affected versions or components (e.g. `pip show appsec_crew`, workflow version)

We aim to acknowledge reports within a few business days. This project is maintained on a best-effort basis.

## Scope notes

- AppSec Crew runs with repository tokens and may invoke third-party CLIs (Betterleaks, OSV-Scanner, Semgrep) and LLM APIs. Review permissions and secrets before enabling in sensitive repositories.
- Findings and automation output may contain file paths or metadata from your codebase; treat CI logs and artifacts accordingly.
