"""Scenario: one evaluation episode.

A scenario bundles a task, the labeled context spans the agent sees, and the
ground truth needed to score a defense: whether an injection is present, which
sink it targets, and what the *correct* decision is.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .types import Span


@dataclass
class Scenario:
    task_id: str
    user_task: str                 # the trusted instruction (plain text)
    spans: list[Span]              # all context spans, already labeled
    # ground truth ------------------------------------------------------------
    has_injection: bool            # does untrusted content carry an attack?
    injection_style: str           # direct | indirect | obfuscated | laundered | none
    target_sink: str | None        # tool the attack (or legit task) aims at
    is_benign_sink_task: bool = False   # a *legit* task that needs a sink
    # the span id carrying the malicious instruction (for laundering studies)
    injected_span_id: int | None = None
    # the span the *model* will attribute the action to (runtime fills this).
    attributed_span_id: int | None = None
    laundering_effort: int = 0     # 0..N, Tier-3 knob
    meta: dict = field(default_factory=dict)

    @property
    def user_span_id(self) -> int:
        for s in self.spans:
            if s.provenance.origin == "user":
                return s.span_id
        return self.spans[0].span_id
