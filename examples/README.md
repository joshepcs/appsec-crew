# AppSec Crew — example configurations

This folder contains drop-in `appsec_crew.yaml` templates for different LLM
providers, plus tool-native allowlist starters.

Copy whichever fits your stack to the **root of the repository you want to
scan** as `appsec_crew.yaml`. The CLI looks there first; if it's missing it
falls back to `src/appsec_crew/bundled_appsec_crew.yaml`.

## LLM provider templates

| File | Provider | Auth secret | Best for |
|------|----------|-------------|----------|
| [`appsec_crew.anthropic-claude.yaml`](appsec_crew.anthropic-claude.yaml) | Anthropic API (Haiku + Sonnet) | `ANTHROPIC_API_KEY` | Deepest reasoning for SAST triage; most consistent JSON output. |
| [`appsec_crew.openai.yaml`](appsec_crew.openai.yaml) | OpenAI API (gpt-4o / gpt-4o-mini) | `OPENAI_API_KEY` | "Default-out-of-the-box" with no provider routing tweaks. |
| [`appsec_crew.github-models.yaml`](appsec_crew.github-models.yaml) | GitHub Models (Copilot's OpenAI-compatible REST) | `GITHUB_TOKEN` (with `models:read`) or a PAT | No extra secret to provision; reuses the existing CI token. |

All three configs scan the same surface (Betterleaks for secrets, OSV-Scanner
for dependencies, Semgrep for SAST), produce the same Markdown report, and
respect the same `min_severity: high` filter. They differ **only** in the four
`agents.*.llm` blocks.

### Picking a model per agent

The configs follow a "small for triage, big for SAST" pattern:

- `secrets_reviewer`, `dependencies_reviewer`, `reporter` → small/fast model
  (Haiku, gpt-4o-mini). These do pattern-matching style triage and Markdown
  rendering; large models add cost, not accuracy.
- `code_reviewer` → larger model (Sonnet, gpt-4o). Semgrep finding triage
  (mock vs. real, cross-file context, framework boilerplate) noticeably
  improves with stronger reasoning.

If you're cost-constrained, drop `code_reviewer` to the small model — the
triage step is opt-in (`tools.semgrep.llm_triage: true`); leave it `false` and
no SAST LLM calls happen at all.

### What is *not* GitHub Models

The `github-models.yaml` template uses `https://models.github.ai/inference`,
the **public, OpenAI-compatible inference endpoint** that any GitHub account
can hit with a PAT (`models:read` scope). It's the supported programmatic path.

It is **not** the GitHub Copilot Chat endpoint (`api.githubcopilot.com`). That
endpoint is meant for first-party clients (VS Code, JetBrains, Copilot CLI)
authenticated via OAuth device flow. Calling it from CI requires a
reverse-engineered token-handling proxy and is typically outside Copilot
Business ToS — avoid for production AppSec automation.

## Tool-native allowlists (provider-agnostic)

These ship side-by-side with the LLM configs and are independent of which
provider you choose:

- [`osv-scanner.toml.example`](osv-scanner.toml.example) — ignore packages /
  vulnerability IDs in OSV-Scanner.
- [`semgrep-local-rules.example.yml`](semgrep-local-rules.example.yml) —
  starter set of repo-local Semgrep rules.

The Betterleaks placeholder (`.betterleaks.toml`) is auto-seeded into the
scanned repo by `ensure_tool_config_files` if you don't ship your own; it
extends the upstream ruleset (`[extend] useDefault = true`) so you only have
to add your own allowlist entries.
