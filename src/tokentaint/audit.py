"""Explainable blocks + audit log.

Every policy decision is recorded with *why*. Blocks render a human-readable
alert naming the untrusted source that tried to trigger the sink -- the sample
that appears in the README.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field

from .types import Decision, PolicyResult


@dataclass
class AuditEntry:
    task_id: str
    tool_name: str
    decision: str
    reason: str
    tainted_origins: list[str] = field(default_factory=list)
    required_trust: str | None = None


class AuditLog:
    def __init__(self):
        self.entries: list[AuditEntry] = []

    def record(self, task_id: str, result: PolicyResult) -> AuditEntry:
        entry = AuditEntry(
            task_id=task_id,
            tool_name=result.action.tool_name,
            decision=result.decision.value,
            reason=result.reason,
            tainted_origins=[s.provenance.origin for s in result.tainted_by],
            required_trust=result.required_trust.name if result.required_trust else None,
        )
        self.entries.append(entry)
        return entry

    def to_json(self) -> str:
        return json.dumps([asdict(e) for e in self.entries], indent=2)


def render_block_alert(result: PolicyResult) -> str:
    """Render the explainable-block message shown to the user."""
    if result.decision == Decision.ALLOW:
        return f"✅ Allowed: {result.action.tool_name}"
    icon = "⛔" if result.decision == Decision.BLOCK else "⚠️"
    verb = "BLOCKED" if result.decision == Decision.BLOCK else "NEEDS YOUR APPROVAL"
    origins = ", ".join(sorted({s.provenance.origin for s in result.tainted_by})) or "unknown"
    lines = [
        f"{icon}  TokenTaint {verb}: {result.action.tool_name}",
        f"    An untrusted source ({origins}) tried to trigger a privileged action.",
        f"    Required trust: {result.required_trust.name if result.required_trust else 'n/a'}",
        f"    Reason: {result.reason}",
    ]
    if result.action.arguments:
        lines.append(f"    Attempted arguments: {result.action.arguments}")
    if result.decision == Decision.ESCALATE:
        lines.append("    → Approve this action? (y/N)")
    return "\n".join(lines)
