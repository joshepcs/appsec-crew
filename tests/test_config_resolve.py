from pathlib import Path

import pytest

from appsec_crew.settings import bundled_default_config_path, resolve_appsec_config_path


def test_resolve_explicit_must_exist(tmp_path: Path) -> None:
    missing = tmp_path / "nope.yaml"
    with pytest.raises(FileNotFoundError):
        resolve_appsec_config_path(tmp_path, missing)


def test_resolve_prefers_repo_local_appsec_crew(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("APPSEC_CREW_CONFIG", raising=False)
    local = tmp_path / "appsec_crew.yaml"
    local.write_text("global:\n  min_severity: low\n  github: {token_env: GITHUB_TOKEN}\nagents: {}\n", encoding="utf-8")
    p, bundled = resolve_appsec_config_path(tmp_path, None)
    assert p == local.resolve()
    assert bundled is False


def test_resolve_bundled_when_no_local(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("APPSEC_CREW_CONFIG", raising=False)
    p, bundled = resolve_appsec_config_path(tmp_path, None)
    assert bundled is True
    assert p == bundled_default_config_path()
    assert p.is_file()


def test_resolve_env_config(tmp_path: Path, monkeypatch) -> None:
    cfg = tmp_path / "from-env.yaml"
    cfg.write_text(
        "global:\n  min_severity: high\n  github: {token_env: GITHUB_TOKEN}\n"
        "agents:\n  secrets_reviewer: {enabled: false, llm: {}, tools: {betterleaks: {}}}\n"
        "  dependencies_reviewer: {enabled: false, llm: {}, tools: {osv_scanner: {}}}\n"
        "  code_reviewer: {enabled: false, llm: {}, tools: {semgrep: {}}}\n"
        "  reporter: {enabled: false, llm: {}, tools: {jira: {enabled: false}, webhook: {enabled: false}, splunk: {enabled: false}}}\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("APPSEC_CREW_CONFIG", str(cfg))
    p, bundled = resolve_appsec_config_path(tmp_path, None)
    assert p == cfg.resolve()
    assert bundled is False


def test_resolve_local_wins_over_env(tmp_path: Path, monkeypatch) -> None:
    env_cfg = tmp_path / "env.yaml"
    env_cfg.write_text("x: 1\n", encoding="utf-8")
    monkeypatch.setenv("APPSEC_CREW_CONFIG", str(env_cfg))
    local = tmp_path / "appsec_crew.yaml"
    local.write_text("global:\n  min_severity: low\n  github: {token_env: GITHUB_TOKEN}\nagents: {}\n", encoding="utf-8")
    p, bundled = resolve_appsec_config_path(tmp_path, None)
    assert p == local.resolve()
    assert bundled is False
