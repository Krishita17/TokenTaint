"""End-to-end firewall: the public, ready-to-use entry point.

`Firewall.run(scenario)` executes one episode: label context, let the agent
propose an action, propagate taint, and let the sink guard decide -- returning a
`PolicyResult` and writing an audit entry. This is what an integrator wires
between their agent loop and their tools.
"""
from __future__ import annotations

from .agent import Agent, SimulatedAgent
from .audit import AuditLog
from .context_store import ContextStore
from .policy import SinkGuard, make_guard
from .scenario import Scenario
from .tools import ToolRegistry, default_registry
from .types import Decision, PolicyResult, ProposedAction


class TokenTaintDefense:
    """Adapts the SinkGuard to the uniform defense interface used in eval."""

    def __init__(self, registry: ToolRegistry, strategy: str = "structural", escalate: bool = False):
        self.name = f"tokentaint_{strategy}"
        self.guard: SinkGuard = make_guard(registry, strategy, escalate_instead_of_block=escalate)

    def evaluate(self, action: ProposedAction, store: ContextStore, scenario: Scenario) -> PolicyResult:
        return self.guard.evaluate(action, store)


class Firewall:
    def __init__(
        self,
        registry: ToolRegistry | None = None,
        agent: Agent | None = None,
        strategy: str = "structural",
        escalate: bool = True,
    ):
        self.registry = registry or default_registry()
        self.agent = agent or SimulatedAgent()
        self.defense = TokenTaintDefense(self.registry, strategy, escalate)
        self.audit = AuditLog()

    def run(self, scenario: Scenario) -> PolicyResult:
        store = ContextStore()
        store.extend(scenario.spans)
        action = self.agent.propose(scenario, store)
        result = self.defense.evaluate(action, store, scenario)
        self.audit.record(scenario.task_id, result)
        return result
