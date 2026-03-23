"""Tests for scanner command logging."""

from __future__ import annotations

import json

from appsec_crew.scanners.command_log import log_tool_command


def test_log_tool_command_stderr_json(capsys) -> None:
    log_tool_command("betterleaks", ["betterleaks", "dir", "a b"])
    err = capsys.readouterr().err
    assert "[appsec-crew] executing:" in err
    payload = json.loads(err.split("executing: ", 1)[1].strip())
    assert payload["tool"] == "betterleaks"
    assert payload["argv"] == ["betterleaks", "dir", "a b"]
    assert "a b" in payload["shell"]
