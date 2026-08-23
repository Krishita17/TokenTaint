"""Core data types for TokenTaint: trust levels, provenance labels, spans, actions.

Everything downstream (labeler, context store, propagation, policy) reads and
writes these structures. Trust levels are an *ordered* enum so the policy engine
can compare "does this source clear the bar this sink requires?".
"""
from __future__ import annotations

import enum
import itertools
from dataclasses import dataclass, field
from typing import Optional


class TrustLevel(enum.IntEnum):
    """Ordered trust levels. Higher == more trusted.

    The ordering is the whole point: a sink can declare "I require at least
    SEMI_TRUSTED justification", and the policy engine just does a numeric
    comparison. Never infer these from content -- they are assigned by the
    harness at ingestion time (see labeler.py) and are outside attacker reach.
    """

    UNTRUSTED = 0      # web pages, fetched docs, emails, third-party tool output
    SEMI_TRUSTED = 1   # first-party tools the operator controls but that echo data
    TRUSTED = 2        # the human user's direct instructions
    SYSTEM = 3         # the harness / developer system prompt


class SourceType(enum.Enum):
    USER = "user"                    # direct human instruction
    SYSTEM = "system"                # developer/system prompt
    TOOL_RESULT = "tool_result"      # output of a first-party tool
    WEB_FETCH = "web_fetch"          # fetched web page
    RETRIEVED_DOC = "retrieved_doc"  # RAG / document store
    EMAIL = "email"                  # inbound message
    UNKNOWN = "unknown"


# Default trust mapping. The harness owns this table; content cannot change it.
DEFAULT_TRUST = {
    SourceType.SYSTEM: TrustLevel.SYSTEM,
    SourceType.USER: TrustLevel.TRUSTED,
    SourceType.TOOL_RESULT: TrustLevel.SEMI_TRUSTED,
    SourceType.WEB_FETCH: TrustLevel.UNTRUSTED,
    SourceType.RETRIEVED_DOC: TrustLevel.UNTRUSTED,
    SourceType.EMAIL: TrustLevel.UNTRUSTED,
    SourceType.UNKNOWN: TrustLevel.UNTRUSTED,
}

_span_ids = itertools.count(1)


@dataclass
class Provenance:
    """The immutable label attached to a span at ingestion time."""

    source_type: SourceType
    trust: TrustLevel
    origin: str  # human-readable origin, e.g. "https://example.com" or "user"

    def is_tainted(self, bar: TrustLevel) -> bool:
        """True if this provenance fails to clear the required trust bar."""
        return self.trust < bar


@dataclass
class Span:
    """A contiguous block of context text with a single provenance label.

    We label at the block/span granularity, not literally per-token: a fetched
    page is one span, a tool result is one span, the user's message is one span.
    "Token-level provenance" in the design means every token *inherits* the label
    of the span it belongs to -- the span is the labeling unit, the token is the
    resolution the policy reasons about.
    """

    text: str
    provenance: Provenance
    span_id: int = field(default_factory=lambda: next(_span_ids))
    # If this span was *produced by the model* from other spans, we record the
    # spans it derived from so taint can propagate through model transforms.
    derived_from: list[int] = field(default_factory=list)

    @property
    def trust(self) -> TrustLevel:
        return self.provenance.trust


@dataclass
class ProposedAction:
    """A tool call the agent wants to make, plus why it wants to make it.

    `justification_span_ids` is the crux of the whole system: which context
    spans caused this action. The propagation engine fills / refines this; the
    policy engine reads it to decide taint.
    """

    tool_name: str
    arguments: dict
    justification_span_ids: list[int] = field(default_factory=list)
    rationale: str = ""


class Decision(enum.Enum):
    ALLOW = "allow"
    BLOCK = "block"
    ESCALATE = "escalate"  # block-and-ask-the-human


@dataclass
class PolicyResult:
    decision: Decision
    action: ProposedAction
    reason: str
    tainted_by: list[Span] = field(default_factory=list)
    required_trust: Optional[TrustLevel] = None
