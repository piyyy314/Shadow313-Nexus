"""Shared base classes for Shadow313 tools (redteam/blueteam/ai/purpleteam)."""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from shadow313.core.output import OutputFormatter


class _ToolOutput:
    """OutputFormatter adapter tolerating the tools' two-arg section() call."""

    def __init__(self) -> None:
        self._fmt = OutputFormatter()

    def section(self, title: str, subtitle: str = "") -> None:
        self._fmt.section(title)
        if subtitle:
            self._fmt.info(subtitle)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._fmt, name)


@dataclass
class ToolResult:
    tool_name: str = ""
    target: str = ""
    findings: list[dict[str, Any]] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)
    started_at: float = field(default_factory=time.time)
    finished_at: float = 0.0

    def finish(self) -> "ToolResult":
        self.finished_at = time.time()
        return self

    @property
    def duration(self) -> float:
        end = self.finished_at or time.time()
        return end - self.started_at

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "target": self.target,
            "findings": self.findings,
            "data": self.data,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration": self.duration,
        }


class BaseTool:
    TOOL_NAME = "base"
    TEAM = "none"
    DESCRIPTION = ""

    def __init__(self, **kwargs: Any) -> None:
        self.output = _ToolOutput()
        self.options = kwargs

    async def run(self, target: str, **kwargs: Any) -> ToolResult:  # pragma: no cover
        raise NotImplementedError

    def ai_context(self, result: ToolResult) -> str:
        return ""
