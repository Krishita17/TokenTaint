"""Tainted context store: the ledger mapping span ids -> provenance.

The store is the single source of truth the propagation and policy engines read.
It also computes the *effective* trust of a derived span (one the model produced
from other spans) as the minimum trust of everything it derived from -- classic
information-flow join: a transform is no more trusted than its least-trusted
input.
"""
from __future__ import annotations

from .types import Span, TrustLevel


class ContextStore:
    def __init__(self):
        self._spans: dict[int, Span] = {}
        self._order: list[int] = []

    def add(self, span: Span) -> Span:
        self._spans[span.span_id] = span
        self._order.append(span.span_id)
        return span

    def extend(self, spans: list[Span]) -> list[Span]:
        for s in spans:
            self.add(s)
        return spans

    def get(self, span_id: int) -> Span:
        return self._spans[span_id]

    def all(self) -> list[Span]:
        return [self._spans[i] for i in self._order]

    def effective_trust(self, span_id: int) -> TrustLevel:
        """Trust of a span accounting for what it derived from.

        A model-produced span (a summary, a paraphrase) is only as trusted as
        the least-trusted span it was built from. This is what makes taint
        *propagate* through the agent's own reasoning rather than being reset to
        trusted just because the model touched it.
        """
        span = self._spans[span_id]
        if not span.derived_from:
            return span.trust
        floor = span.trust
        for parent_id in span.derived_from:
            if parent_id in self._spans:
                floor = min(floor, self.effective_trust(parent_id))
        return floor

    def is_tainted(self, span_id: int, bar: TrustLevel) -> bool:
        return self.effective_trust(span_id) < bar

    def __len__(self) -> int:
        return len(self._spans)
