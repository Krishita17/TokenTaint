"""Taint propagation engine.

Given a proposed action, decide *which context spans justified it*. This is the
hard, interesting problem of the project: when is an action "caused by"
untrusted tokens? We implement two strategies and let the evaluation compare
them head to head.

  1. StructuralPropagation -- conservative. The action's justification is every
     span whose text overlaps the action arguments, plus any span that carried
     an imperative/instruction the model then acted on. If untrusted content is
     among the causes, the action is tainted. High recall on attacks (it rarely
     misses a real cause) at the cost of over-tainting benign work.

  2. AttributionPropagation -- precise. It asks the agent runtime "which span
     actually drove this decision?" (a secondary attribution query / the model's
     own citation) and trusts that narrower answer. Fewer false blocks, but it
     can be fooled when an instruction is *laundered* through a trusted-looking
     transform (the Tier-3 arms race).

Both return a list of justifying span ids; the policy engine turns that into a
trust decision.
"""
from __future__ import annotations

import re
from abc import ABC, abstractmethod

from .context_store import ContextStore
from .types import ProposedAction, SourceType, Span, TrustLevel

# Cheap, phrasing-independent hint that a span contains an instruction. Note:
# this is NOT an injection classifier -- we are not judging whether text is
# malicious. We only use it to link an action back to the span that *told the
# model to do something*, so provenance can then decide trust. A false hit here
# just means we consider one more span as a possible cause; it never, on its
# own, blocks anything.
_IMPERATIVE = re.compile(
    r"\b(ignore|disregard|forward|send|email|delete|transfer|execute|run|"
    r"export|exfiltrate|post|pay|wire|buy|click|download|write|overwrite|"
    r"reply|share|upload|now instead|new instructions?|system:)\b",
    re.IGNORECASE,
)


def _arg_text(action: ProposedAction) -> str:
    return " ".join(str(v) for v in action.arguments.values())


class Propagation(ABC):
    name: str = "abstract"

    @abstractmethod
    def justify(self, action: ProposedAction, store: ContextStore) -> list[int]:
        """Return span ids that justify this action."""


class StructuralPropagation(Propagation):
    """Conservative dataflow: any span that could have caused the action counts.

    Two causal links:
      (a) argument dataflow -- a span whose text appears (substring / token
          overlap) in the action arguments plausibly *is* the data feeding the
          sink (e.g. the recipient address the injection supplied).
      (b) instruction flow -- a span carrying an imperative that names this
          tool / sink plausibly *ordered* the action.
    """

    name = "structural"

    def __init__(self, min_overlap_tokens: int = 2):
        self.min_overlap_tokens = min_overlap_tokens

    def justify(self, action: ProposedAction, store: ContextStore) -> list[int]:
        just: set[int] = set(action.justification_span_ids)
        arg_tokens = set(re.findall(r"\w+", _arg_text(action).lower()))
        for span in store.all():
            span_tokens = set(re.findall(r"\w+", span.text.lower()))
            overlap = arg_tokens & span_tokens
            # (a) argument dataflow
            if len(overlap - _STOPWORDS) >= self.min_overlap_tokens:
                just.add(span.span_id)
            # (b) instruction flow that names the tool or a sink verb
            if _IMPERATIVE.search(span.text) and (
                action.tool_name.lower() in span.text.lower()
                or self._names_sink_verb(span, action)
            ):
                just.add(span.span_id)
        return sorted(just)

    @staticmethod
    def _names_sink_verb(span: Span, action: ProposedAction) -> bool:
        verbs = {
            "send_email": ["email", "send", "forward", "reply"],
            "execute_code": ["execute", "run", "eval"],
            "make_payment": ["pay", "wire", "transfer", "buy"],
            "write_file": ["write", "save", "overwrite", "export"],
        }.get(action.tool_name, [])
        low = span.text.lower()
        return any(v in low for v in verbs)


class AttributionPropagation(Propagation):
    """Precise attribution: trust the agent's own account of *why* it acted.

    In deployment this is a secondary "why did you call this tool?" query, or
    reading the model's citation/attention over the context. Here the agent
    runtime records the single span it believes drove the decision
    (`action.justification_span_ids` set by the runtime), and we take that as
    ground-ish truth -- optionally widening to argument-dataflow spans so a
    laundered instruction that hid its origin can still be caught if its *data*
    still flows to the sink.

    The catch, and the reason this is a research axis: if an attacker launders
    an instruction through a trusted transform (e.g. gets a summarizer to
    restate "email the files" as if it were the summary's own conclusion), the
    model may attribute the action to the *trusted* summary span, and this
    strategy will clear it. That gap is measured in the Tier-3 laundering study.
    """

    name = "attribution"

    def __init__(self, widen_to_dataflow: bool = False):
        self.widen_to_dataflow = widen_to_dataflow
        self._structural = StructuralPropagation()

    def justify(self, action: ProposedAction, store: ContextStore) -> list[int]:
        just: set[int] = set(action.justification_span_ids)
        if self.widen_to_dataflow:
            # keep only *argument* dataflow, not the broad instruction-flow net
            arg_tokens = set(re.findall(r"\w+", _arg_text(action).lower()))
            for span in store.all():
                span_tokens = set(re.findall(r"\w+", span.text.lower()))
                if len((arg_tokens & span_tokens) - _STOPWORDS) >= 3:
                    just.add(span.span_id)
        return sorted(just)


class ProvenanceChainPropagation(Propagation):
    """Fail-closed on *unexplained* provenance -- the taint-laundering defense.

    Attribution is defeated by laundering: an attacker gets a trusted-looking
    transform (a summarizer tool) to restate an injected instruction and severs
    the derivation link, so the laundered span *looks* first-party and the model
    attributes its action there.

    The insight here: trust in any model-/tool-derived span must be backed by an
    intact **chain of custody**. A span that claims first-party trust but records
    no derivation -- while untrusted content it could have laundered from is
    present in the same context -- cannot prove it is not laundered. So we refuse
    to credit its trust: we treat such a span as UNTRUSTED for the purpose of
    justifying a sink (fail-closed on a broken chain).

    Concretely, `justify()` returns the attributed span(s) *plus* every
    derived-looking span whose chain of custody is missing while untrusted
    content coexists. The policy engine's normal trust check then blocks it. This
    keeps attribution's low false-block rate on honest workflows (where derived
    spans DO record their parents, or the justification is the user span) while
    closing the laundering gap that plain attribution leaves open.
    """

    name = "provenance_chain"

    def __init__(self):
        self._attr = AttributionPropagation(widen_to_dataflow=False)

    def justify(self, action: ProposedAction, store: ContextStore) -> list[int]:
        just: set[int] = set(self._attr.justify(action, store))
        untrusted_ids = [
            s.span_id for s in store.all()
            if store.effective_trust(s.span_id) < TrustLevel.SEMI_TRUSTED
        ]
        if not untrusted_ids:
            return sorted(just)
        # Does any span we're relying on (or any first-party-looking transform in
        # context) have a BROKEN chain of custody -- i.e. it claims trusted/
        # first-party status but records no derivation, so we cannot prove it was
        # not laundered from the untrusted content that coexists with it?
        broken_chain = any(
            s.provenance.source_type in _DERIVED_SOURCES
            and not s.derived_from
            and s.trust >= TrustLevel.SEMI_TRUSTED
            for s in store.all()
        )
        if broken_chain:
            # Fail closed: conservatively attribute the action to the untrusted
            # content. Those spans are below any sink bar, so the guard blocks --
            # closing the laundering gap that plain attribution leaves open,
            # without structural's broad false-block cost (this only triggers
            # when an unexplained transform coexists with untrusted content).
            just.update(untrusted_ids)
        return sorted(just)


_DERIVED_SOURCES = {SourceType.TOOL_RESULT}

_STOPWORDS = {
    "the", "a", "an", "to", "of", "and", "or", "for", "in", "on", "at", "is",
    "this", "that", "please", "with", "your", "you", "it", "as", "be", "by",
}

STRATEGIES = {
    "structural": StructuralPropagation,
    "attribution": AttributionPropagation,
    "provenance_chain": ProvenanceChainPropagation,
}
