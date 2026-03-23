# Contributing

Thanks for helping improve AppSec Crew.

## Getting started

```bash
git clone https://github.com/celagus/appsec-crew.git
cd appsec-crew
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest
```

## Local verification

1. **Unit tests (start here)** — no API keys or scanners:
   ```bash
   pip install -e ".[dev]"
   pytest -v
   # optional coverage (requires pytest-cov, included in [dev]):
   pytest -q --cov=appsec_crew --cov-report=term-missing
   ```

2. **CLI smoke** — verifies the entrypoint and config resolution. With default/bundled config and no `OPENAI_API_KEY`, expect exit code **3** and a message about LLM keys:
   ```bash
   appsec-crew --repo .
   ```

3. **End-to-end** — see [README § Local usage](./README.md#local-usage): put **betterleaks**, **osv-scanner**, and **semgrep** on `PATH`, set `GITHUB_TOKEN`, `GITHUB_REPOSITORY=owner/repo`, and `OPENAI_API_KEY`, then `appsec-crew --repo /path/to/repo-to-scan`. This hits real scanners and GitHub (issues/PRs).

By participating, you agree to abide by the [Code of Conduct](./CODE_OF_CONDUCT.md).

## Pull requests

1. Open an issue first for large features or design changes (optional but appreciated).
2. Keep changes focused on one concern per PR.
3. Run `pytest` locally; fix failures before requesting review.
4. Update `README.md` or examples if behavior or configuration changes.

## Code style

- Match existing patterns in the codebase (typing, imports, error handling).
- Prefer small, reviewable diffs over drive-by refactors.

## Security

Do not commit secrets, tokens, or internal URLs. See [SECURITY.md](./SECURITY.md).
