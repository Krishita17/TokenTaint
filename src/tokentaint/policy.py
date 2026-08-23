"""Policy / sink guard: the enforcement point.

Rule (phrasing-independent, this is the whole guarantee):

    A privileged sink fires only if *every* span that justifies the call
    clears the sink's required trust level. If any justifying span is tainted
    (below the bar), the call is blocked -- or escalated to the human, who is a
    trusted source and can clear it.

Non-privileged tools flow freely regardless of taint, so the agent stays useful
on untrusted content. The guard never inspects *what the text says*; it only
asks *where the justification came from*. That is why rephrasing an injection
does not help the attacker.
"""
from __future__ import annotations

from .context_store import ContextStore
from .propagation import Propagation
from .tools import ToolRegistry
from .types import Decision, PolicyResult, ProposedAction, TrustLevel


class SinkGuard:
    def __init__(
        self,
        registry: ToolRegistry,
        propagation: Propagation,
        escalate_instead_of_block: bool = True,
        authority=None,
    ):
        self.registry = registry
        self.propagation = propagation
        # If True, a tainted sink call becomes a human-approval prompt rather
        # than a hard block. That is the deployable default: it preserves
        # utility (the human can say yes) while still stopping autonomous
        # injection-driven actions.
        self.escalate = escalate_instead_of_block
        # Optional CapabilityAuthority. If set, a tainted sink call carrying a
        # valid capability endorsement (a logged declassification by a trusted
        # principal) is allowed -- this is how human-in-the-loop "approve"
        # becomes a tamper-evident, single-use grant instead of a soft prompt.
        self.authority = authority

    def evaluate(self, action: ProposedAction, store: ContextStore) -> PolicyResult:
        tool = self.registry.get(action.tool_name)
        if tool is None:
            return PolicyResult(
                Decision.BLOCK, action, reason=f"unknown tool '{action.tool_name}'"
            )

        # Non-sink tools: always allow. Keeps the agent useful.
        if not tool.is_sink:
            return PolicyResult(Decision.ALLOW, action, reason="non-privileged tool")

        bar = tool.required_trust
        # Ask the propagation engine which spans justified this action.
        justifying_ids = self.propagation.justify(action, store)

        tainted = [
            store.get(sid)
            for sid in justifying_ids
            if sid in _existing(store) and store.is_tainted(sid, bar)
        ]

        if not tainted:
            return PolicyResult(
                Decision.ALLOW,
                action,
                reason="justification clears required trust",
                required_trust=bar,
            )

        # Tainted -- but a valid capability endorsement can declassify this one
        # action. The grant is verified against the authority's secret key, is
        # bound to these exact arguments, is single-use, and is logged.
        if self.authority is not None and action.endorsement is not None:
            ok, why = self.authority.verify(action, action.endorsement)
            if ok and action.endorsement.granted_trust >= bar:
                self.authority.spend(action.endorsement)
                return PolicyResult(
                    Decision.ALLOW,
                    action,
                    reason=(f"declassified by capability from "
                            f"'{action.endorsement.principal}' (single-use)"),
                    required_trust=bar,
                )

        decision = Decision.ESCALATE if self.escalate else Decision.BLOCK
        return PolicyResult(
            decision,
            action,
            reason=(
                f"privileged sink '{tool.name}' justified by "
                f"{len(tainted)} untrusted span(s); needs {bar.name}"
            ),
            tainted_by=tainted,
            required_trust=bar,
        )


def _existing(store: ContextStore) -> set[int]:
    return {s.span_id for s in store.all()}


def make_guard(registry: ToolRegistry, strategy: str = "structural", **kw) -> SinkGuard:
    from .propagation import STRATEGIES

    prop = STRATEGIES[strategy]()
    return SinkGuard(registry, prop, **kw)
