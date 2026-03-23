"""Tests for ``run_scanner`` wrapper."""

from __future__ import annotations

from pathlib import Path

from appsec_crew.scanners.subprocess_run import run_scanner


def test_run_scanner_capture_output(tmp_path: Path) -> None:
    proc = run_scanner(["echo", "hello"], cwd=tmp_path, tool_label="test-tool")
    assert proc.returncode == 0
    assert proc.stdout is not None
    assert "hello" in proc.stdout


def test_run_scanner_commands_log(tmp_path: Path) -> None:
    log: list[str] = []
    run_scanner(["echo", "x"], cwd=tmp_path, tool_label="t", commands_log=log)
    assert len(log) == 1
    assert "echo" in log[0]
