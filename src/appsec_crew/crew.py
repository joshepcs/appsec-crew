"""Build a sequential Crew with only enabled agents."""

from __future__ import annotations

from pathlib import Path

import yaml
from crewai import Agent, Crew, Process, Task

from appsec_crew.utils.llm import build_llm
from appsec_crew.runtime import RuntimeContext
from appsec_crew.settings import AppSecSettings
from appsec_crew.workflow_tools import (
    CodeReviewerTool,
    DependenciesReviewerTool,
    ReporterTool,
    SecretsReviewerTool,
)


def _config_dir() -> Path:
    return Path(__file__).resolve().parent / "config"


def _agent_block(settings: AppSecSettings, key: str):
    return getattr(settings, key)


def build_appsec_crew(ctx: RuntimeContext) -> Crew:
    agents_yaml = yaml.safe_load((_config_dir() / "agents.yaml").read_text(encoding="utf-8"))
    tasks_yaml = yaml.safe_load((_config_dir() / "tasks.yaml").read_text(encoding="utf-8"))

    agents: list[Agent] = []
    tasks: list[Task] = []

    specs: list[tuple[str, type, str]] = [
        ("secrets_reviewer", SecretsReviewerTool, "secrets_reviewer_task"),
        ("dependencies_reviewer", DependenciesReviewerTool, "dependencies_reviewer_task"),
        ("code_reviewer", CodeReviewerTool, "code_reviewer_task"),
        ("reporter", ReporterTool, "reporter_task"),
    ]

    for agent_key, tool_cls, task_key in specs:
        block = _agent_block(ctx.settings, agent_key)
        if not block.enabled:
            continue
        llm = build_llm(block.llm)
        if llm is None:
            raise RuntimeError(
                f"Agent '{agent_key}' is enabled but no LLM API key resolved "
                f"(set llm.api_key in appsec_crew.yaml or {block.llm.api_key_env})."
            )
        agent = Agent(
            config=agents_yaml[agent_key],
            tools=[tool_cls()],
            llm=llm,
            allow_delegation=False,
            verbose=True,
        )
        agents.append(agent)
        tc = tasks_yaml[task_key]
        tasks.append(
            Task(
                description=tc["description"],
                expected_output=tc["expected_output"],
                agent=agent,
            )
        )

    if not agents:
        raise RuntimeError("No agents enabled; enable at least one role in appsec_crew.yaml.")

    return Crew(agents=agents, tasks=tasks, process=Process.sequential, verbose=True)
