"""Tests for Semgrep command building and language detection."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from appsec_crew.scanners.semgrep_scan import (
    build_semgrep_command,
    build_semgrep_config_args,
    detect_primary_language,
    run_semgrep,
)


def test_build_semgrep_command_default(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    report = tmp_path / "rep.json"
    cmd = build_semgrep_command(repo, "semgrep", ["--config", "auto"], report)
    assert cmd[0] == "semgrep"
    assert cmd[1] == "scan"
    assert "--config" in cmd
    assert "auto" in cmd
    assert "--json" in cmd
    assert str(report) in cmd
    assert cmd[-1] == str(repo.resolve())


def test_build_semgrep_command_autofix_and_extra_args(tmp_path: Path) -> None:
    repo = tmp_path / "r"
    repo.mkdir()
    report = tmp_path / "out.json"
    cmd = build_semgrep_command(
        repo,
        "semgrep",
        ["--config", "p/python"],
        report,
        autofix=True,
        extra_args=["--timeout", "0"],
    )
    assert "--autofix" in cmd
    assert "--timeout" in cmd
    assert "0" in cmd


def test_build_semgrep_command_template(tmp_path: Path) -> None:
    repo = tmp_path / "r"
    repo.mkdir()
    report = tmp_path / "out.json"
    tpl = "{binary} scan {autofix}--config p/ci {config_args} --json -o {report} {repo}"
    cmd = build_semgrep_command(
        repo,
        "semgrep",
        ["--config", "auto"],
        report,
        command_template=tpl,
    )
    assert cmd[0] == "semgrep"
    assert "--json" in cmd
    assert str(report) in cmd


def test_build_semgrep_config_args_repo_yaml(tmp_path: Path) -> None:
    (tmp_path / ".semgrep.yml").write_text("rules: []\n", encoding="utf-8")
    args = build_semgrep_config_args(tmp_path, None, ["p/python"])
    assert args[:2] == ["--config", str(tmp_path / ".semgrep.yml")]
    assert "--config" in args
    assert "p/python" in args


def test_build_semgrep_config_args_configured_path(tmp_path: Path) -> None:
    cfg = tmp_path / "rules.yaml"
    cfg.write_text("rules: []\n", encoding="utf-8")
    args = build_semgrep_config_args(tmp_path, cfg, [])
    assert args == ["--config", str(cfg)]


def test_detect_primary_language_from_extensions(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("x", encoding="utf-8")
    (tmp_path / "b.py").write_text("y", encoding="utf-8")
    (tmp_path / "c.js").write_text("z", encoding="utf-8")
    assert detect_primary_language(tmp_path) == "python"


def test_detect_primary_language_empty_repo(tmp_path: Path) -> None:
    assert detect_primary_language(tmp_path) == "python"


def test_run_semgrep_returns_empty_when_report_missing(tmp_path: Path) -> None:
    repo = tmp_path / "r"
    repo.mkdir()
    report = tmp_path / "out.json"
    proc = MagicMock(returncode=1, stdout="", stderr="")
    with patch("appsec_crew.scanners.semgrep_scan.run_scanner", return_value=proc):
        findings = run_semgrep(repo, "semgrep", [], report)
    assert findings == []
    assert not report.is_file()


def test_run_semgrep_returns_empty_on_invalid_json(tmp_path: Path) -> None:
    repo = tmp_path / "r"
    repo.mkdir()
    report = tmp_path / "out.json"
    report.write_text("not-json{{{", encoding="utf-8")
    proc = MagicMock(returncode=0, stdout="", stderr="")
    with patch("appsec_crew.scanners.semgrep_scan.run_scanner", return_value=proc):
        findings = run_semgrep(repo, "semgrep", [], report)
    assert findings == []


def test_run_semgrep_parses_results(tmp_path: Path) -> None:
    repo = tmp_path / "r"
    repo.mkdir()
    report = tmp_path / "out.json"
    report.write_text(
        '{"results": [{"check_id": "x", "path": "a.py"}], "errors": [], "paths": {}}',
        encoding="utf-8",
    )
    proc = MagicMock(returncode=0, stdout="", stderr="")
    with patch("appsec_crew.scanners.semgrep_scan.run_scanner", return_value=proc):
        findings = run_semgrep(repo, "semgrep", [], report)
    assert len(findings) == 1
    assert findings[0]["check_id"] == "x"
