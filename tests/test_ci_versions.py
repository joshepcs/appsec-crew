"""Tests for ``appsec_crew.ci_versions`` (GitHub Actions version emission)."""

from __future__ import annotations

import yaml

from appsec_crew import ci_versions


def _minimal_agents() -> dict:
    return {
        "secrets_reviewer": {
            "enabled": False,
            "llm": {"api_key": "x"},
            "tools": {"betterleaks": {"version": "v9.9.9-bl"}},
        },
        "dependencies_reviewer": {
            "enabled": False,
            "llm": {"api_key": "x"},
            "tools": {"osv_scanner": {"version": "v8.8.8-osv"}},
        },
        "code_reviewer": {
            "enabled": False,
            "llm": {"api_key": "x"},
            "tools": {"semgrep": {"version": "7.7.7"}},
        },
        "reporter": {
            "enabled": False,
            "llm": {"api_key": "x"},
            "tools": {
                "jira": {"enabled": False},
                "webhook": {"enabled": False},
                "splunk": {"enabled": False},
            },
        },
    }


def test_ci_versions_main_stdout(tmp_path, monkeypatch, capsys) -> None:
    monkeypatch.delenv("GITHUB_OUTPUT", raising=False)
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    repo = tmp_path / "scan"
    repo.mkdir()
    assert ci_versions.main(["--repo", str(repo)]) == 0
    out = capsys.readouterr().out
    assert "betterleaks_version=" in out
    assert "osv_scanner_version=" in out
    assert "semgrep_version=" in out


def test_ci_versions_writes_github_output(tmp_path, monkeypatch) -> None:
    gho = tmp_path / "github_out"
    gho.write_text("", encoding="utf-8")
    monkeypatch.setenv("GITHUB_OUTPUT", str(gho))
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    repo = tmp_path / "scan"
    repo.mkdir()
    assert ci_versions.main(["--repo", str(repo)]) == 0
    text = gho.read_text(encoding="utf-8")
    assert "betterleaks_version=" in text
    assert text.count("\n") >= 3


def test_ci_versions_explicit_config(tmp_path, monkeypatch, capsys) -> None:
    monkeypatch.delenv("GITHUB_OUTPUT", raising=False)
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    repo = tmp_path / "scan"
    repo.mkdir()
    cfg = tmp_path / "custom.yaml"
    cfg.write_text(
        yaml.safe_dump({"global": {"github": {}}, "agents": _minimal_agents()}),
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    assert ci_versions.main(["--repo", str(repo), "--config", "custom.yaml"]) == 0
    out = capsys.readouterr().out
    assert "betterleaks_version=v9.9.9-bl" in out
    assert "osv_scanner_version=v8.8.8-osv" in out
    assert "semgrep_version=7.7.7" in out
