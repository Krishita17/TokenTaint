"""TokenTaint -- a provenance-tracking firewall for LLM agent prompt injection.

Public API::

    from tokentaint import Firewall, Labeler
    from tokentaint.tools import default_registry
    from tokentaint.scenario import Scenario

TokenTaint labels every span of an agent's context with its source of trust,
propagates that taint through the agent's reasoning, and refuses to let a
privileged tool ("sink") fire when its justification traces to an untrusted
origin -- a structural guarantee that does not depend on recognizing the
injection's phrasing.
"""
from .agent import Agent, LLMAgent, SimulatedAgent
from .audit import AuditLog, render_block_alert
from .capabilities import Capability, CapabilityAuthority
from .context_store import ContextStore
from .firewall import Firewall, TokenTaintDefense
from .integrity import ProvenanceSigner, SignedContextStore, SignedProvenance
from .labeler import Labeler
from .policy import SinkGuard, make_guard
from .propagation import (
    AttributionPropagation,
    ProvenanceChainPropagation,
    StructuralPropagation,
)
from .scenario import Scenario
from .tools import Tool, ToolRegistry, default_registry
from .types import (
    Decision,
    PolicyResult,
    ProposedAction,
    Provenance,
    SourceType,
    Span,
    TrustLevel,
)

__version__ = "0.1.0"

__all__ = [
    "Firewall",
    "TokenTaintDefense",
    "Labeler",
    "ContextStore",
    "SinkGuard",
    "make_guard",
    "StructuralPropagation",
    "AttributionPropagation",
    "ProvenanceChainPropagation",
    "Capability",
    "CapabilityAuthority",
    "ProvenanceSigner",
    "SignedContextStore",
    "SignedProvenance",
    "Scenario",
    "Agent",
    "SimulatedAgent",
    "LLMAgent",
    "AuditLog",
    "render_block_alert",
    "Tool",
    "ToolRegistry",
    "default_registry",
    "Decision",
    "PolicyResult",
    "ProposedAction",
    "Provenance",
    "SourceType",
    "Span",
    "TrustLevel",
    "__version__",
]
