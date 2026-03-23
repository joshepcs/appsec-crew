"""Semgrep scan, severity filtering, and primary language hint."""

from __future__ import annotations

import json
import subprocess
from collections import Counter
from pathlib import Path
from typing import Any


LANG_EXTENSIONS: dict[str, tuple[str, ...]] = {
    "python": (".py", ".pyi"),
    "javascript": (".js", ".jsx", ".mjs", ".cjs"),
    "typescript": (".ts", ".tsx"),
    "go": (".go",),
    "java": (".java",),
    "kotlin": (".kt", ".kts"),
    "ruby": (".rb",),
    "php": (".php",),
    "csharp": (".cs",),
    "rust": (".rs",),
}


def detect_primary_language(repo: Path, max_files: int = 8000) -> str:
    counts: Counter[str] = Counter()
    n = 0
    for path in repo.rglob("*"):
        if not path.is_file() or n >= max_files:
            break
        if ".git" in path.parts or "node_modules" in path.parts or "vendor" in path.parts:
            continue
        suf = path.suffix.lower()
        for lang, exts in LANG_EXTENSIONS.items():
            if suf in exts:
                counts[lang] += 1
                n += 1
                break
    if not counts:
        return "python"
    return counts.most_common(1)[0][0]


def build_semgrep_config_args(repo: Path, configured: Path | None, extras: list[str]) -> list[str]:
    """Return flattened `--config` CLI args (repo YAML first, then registry packs from `extras`)."""
    args: list[str] = []
    if configured and configured.is_file():
        args += ["--config", str(configured)]
    else:
        for candidate in (repo / ".semgrep.yml", repo / ".semgrep.yaml"):
            if candidate.is_file():
                args += ["--config", str(candidate)]
                break
    for e in extras:
        if e:
            args += ["--config", str(e)]
    return args


def run_semgrep(
    repo: Path,
    binary: str,
    config_args: list[str],
    report_path: Path,
    autofix: bool = False,
) -> list[dict[str, Any]]:
    cmd = [binary, "scan", *config_args, "--json", "-o", str(report_path), str(repo)]
    if autofix:
        cmd.insert(2, "--autofix")
    subprocess.run(cmd, cwd=str(repo), text=True, capture_output=True)
    if not report_path.is_file():
        return []
    raw = report_path.read_text(encoding="utf-8", errors="replace").strip()
    if not raw:
        return []
    data = json.loads(raw)
    res = data.get("results")
    if isinstance(res, list):
        return [x for x in res if isinstance(x, dict)]
    return []
