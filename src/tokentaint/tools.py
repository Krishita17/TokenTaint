"""Tool registry: safe tools and declared privileged *sinks*.

A sink is a tool that can cause real-world harm (exfiltration, spend, code
execution, persistent writes). Each sink declares the minimum trust its
*justification* must clear. Safe tools declare UNTRUSTED (anyone may trigger
them) so the agent stays useful on untrusted content.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from .types import TrustLevel


@dataclass
class Tool:
    name: str
    description: str
    # Minimum trust the *justification* for calling this tool must clear.
    # A privileged sink sets this above UNTRUSTED so injected (untrusted)
    # instructions can never trigger it on their own.
    required_trust: TrustLevel
    handler: Callable[..., str]
    is_sink: bool

    def __call__(self, **kwargs) -> str:
        return self.handler(**kwargs)


class ToolRegistry:
    def __init__(self):
        self._tools: dict[str, Tool] = {}

    def register(self, tool: Tool) -> Tool:
        self._tools[tool.name] = tool
        return tool

    def get(self, name: str) -> Tool | None:
        return self._tools.get(name)

    def sinks(self) -> list[Tool]:
        return [t for t in self._tools.values() if t.is_sink]

    def __contains__(self, name: str) -> bool:
        return name in self._tools

    def __iter__(self):
        return iter(self._tools.values())


# ---- reference handlers (side-effect free stand-ins for the demo) ------------

def _noop(**kwargs) -> str:
    return f"ok:{kwargs}"


def default_registry() -> ToolRegistry:
    """A small default toolset: safe tools + one of each sink class."""
    reg = ToolRegistry()
    # safe tools -- always allowed, keep the agent useful on untrusted content
    reg.register(Tool("summarize", "Summarize provided text", TrustLevel.UNTRUSTED, _noop, is_sink=False))
    reg.register(Tool("search", "Search the web", TrustLevel.UNTRUSTED, _noop, is_sink=False))
    reg.register(Tool("read_file", "Read a local file", TrustLevel.UNTRUSTED, _noop, is_sink=False))
    # privileged sinks -- require trusted justification
    reg.register(Tool("send_email", "Send an email", TrustLevel.TRUSTED, _noop, is_sink=True))
    reg.register(Tool("execute_code", "Execute code", TrustLevel.TRUSTED, _noop, is_sink=True))
    reg.register(Tool("make_payment", "Move money", TrustLevel.TRUSTED, _noop, is_sink=True))
    reg.register(Tool("write_file", "Write/overwrite a file", TrustLevel.SEMI_TRUSTED, _noop, is_sink=True))
    return reg
