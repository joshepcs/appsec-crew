"""Run scanner subprocesses with stderr logging of argv."""

from __future__ import annotations

import shlex
import subprocess
from pathlib import Path
from typing import Any

from appsec_crew.scanners.command_log import log_tool_command


def run_scanner(
    cmd: list[str],
    *,
    cwd: Path,
    tool_label: str,
    commands_log: list[str] | None = None,
) -> subprocess.CompletedProcess[Any]:
    """Run a scanner subprocess; capture stdout/stderr for debugging failed runs."""
    log_tool_command(tool_label, cmd)
    if commands_log is not None:
        commands_log.append(shlex.join(cmd))
    ret = subprocess.run(cmd, cwd=str(cwd), text=True, capture_output=True)
    print("cmd:", cmd ,"...")
    print("cwd:", cwd ,"...")
    print("stdout1:", ret.stdout,"...")
    print("stderr1:", ret.stderr,"...")
    tmp_ret = subprocess.run(["find","/tmp","-name","'*.json'","-exec","cat","{}","\;"],cwd=str(cwd), text=True, capture_output=True)
    print("stdout-find:", tmp_ret.stdout,"...")
    tmp_ret = subprocess.run(["betterleaks","dir","--no-banner","-f","json","-r","/tmp/bl.json",str(cwd)],cwd=str(cwd), text=True, capture_output=True)
    print("stdout-bl:", tmp_ret.stdout,"...")
    print("stderr:", tmp_ret.stderr,"...")
    tmp_ret = subprocess.run(["ls","/tmp/bl.json"],cwd=str(cwd), text=True, capture_output=True)
    print("stdout-ls:", tmp_ret.stdout,"...")
    tmp_ret = subprocess.run(["cat","/tmp/bl.json"],cwd=str(cwd), text=True, capture_output=True)
    print("stdout-cat:", tmp_ret.stdout,"...")
    print("stderr:", tmp_ret.stderr,"...")
    tmp_ret = subprocess.run(["cat",str(cwd)+"/app/config_insecure.py"],cwd=str(cwd), text=True, capture_output=True)
    print("stdout-cat:", tmp_ret.stdout,"...")
    print("stderr:", tmp_ret.stderr,"...")
    return ret 