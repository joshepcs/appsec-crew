"""Tests for default tool versions loaded from ``bundled_appsec_crew.yaml``."""

from __future__ import annotations

import yaml

import pytest

from appsec_crew.settings import bundled_default_config_path, bundled_default_tool_versions


def test_bundled_default_tool_versions_reads_package_bundle() -> None:
    bundled_default_tool_versions.cache_clear()
    tv = bundled_default_tool_versions()
    assert tv.betterleaks
    assert tv.betterleaks.startswith("v")
    assert tv.osv_scanner
    assert tv.osv_scanner.startswith("v")
    assert tv.semgrep
    path = bundled_default_config_path()
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    agents = raw.get("agents") or {}
    bl = (agents.get("secrets_reviewer") or {}).get("tools", {}).get("betterleaks") or {}
    assert tv.betterleaks == str(bl.get("version", "")).strip()


def test_bundled_default_tool_versions_raises_if_version_missing(monkeypatch, tmp_path) -> None:
    bundled_default_tool_versions.cache_clear()
    bad = tmp_path / "bad_bundle.yaml"
    bad.write_text(
        yaml.safe_dump(
            {
                "global": {"github": {}},
                "agents": {
                    "secrets_reviewer": {"tools": {"betterleaks": {"version": "v1"}}},
                    "dependencies_reviewer": {"tools": {"osv_scanner": {}}},
                    "code_reviewer": {"tools": {"semgrep": {"version": "1.0.0"}}},
                },
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr("appsec_crew.settings.bundled_default_config_path", lambda: bad)
    with pytest.raises(ValueError, match="non-empty"):
        bundled_default_tool_versions()
    bundled_default_tool_versions.cache_clear()
