"""Unforgeable provenance labels (tamper-evident taint).

The security model assumes the labeler is trusted and content cannot forge its
origin. But once spans are *serialized* -- passed between processes, cached,
persisted, or shuttled through a context whose representation an attacker can
influence -- a plain label is just a field an attacker might try to overwrite
("relabel my injected web span as USER/TRUSTED").

This module makes the label **tamper-evident**: the harness signs each span's
provenance with an HMAC keyed by a secret only the harness holds. Any later
mutation of the text or the label invalidates the signature, and the sink guard
can be configured to *fail closed* on any span whose signature does not verify.

This is the integrity leg of provenance integrity -- and, applied at the
token/span level of an LLM context, a novel transplant of message-authentication
into agent memory.
"""
from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass

from .types import Span


def _canonical(span: Span) -> bytes:
    """A stable byte encoding of the security-relevant fields of a span.

    Deliberately covers text + provenance + derivation: changing any of them
    (relabelling, editing the text, or rewriting the chain of custody) breaks
    the signature.
    """
    p = span.provenance
    parts = [
        str(span.span_id),
        span.text,
        p.source_type.value,
        str(int(p.trust)),
        p.origin,
        ",".join(str(d) for d in sorted(span.derived_from)),
    ]
    return "\x1f".join(parts).encode("utf-8")


@dataclass
class SignedProvenance:
    """A detached signature over a span, held by the harness alongside it."""

    span_id: int
    signature: str


class ProvenanceSigner:
    """Signs and verifies span provenance with a harness-held secret key.

    Generate one per process (or load from a secret manager). The key never
    enters the model's context -- it is infrastructure, not data.
    """

    def __init__(self, key: bytes | None = None):
        self.key = key or os.urandom(32)

    def sign(self, span: Span) -> SignedProvenance:
        sig = hmac.new(self.key, _canonical(span), hashlib.sha256).hexdigest()
        return SignedProvenance(span_id=span.span_id, signature=sig)

    def verify(self, span: Span, signed: SignedProvenance) -> bool:
        if signed.span_id != span.span_id:
            return False
        expected = hmac.new(self.key, _canonical(span), hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, signed.signature)


class SignedContextStore:
    """A context store that signs every span on ingest and can verify integrity.

    `verify_all()` returns the spans whose signatures fail -- a guard can treat
    those as UNTRUSTED regardless of their claimed label (fail-closed).
    """

    def __init__(self, signer: ProvenanceSigner | None = None):
        from .context_store import ContextStore

        self.signer = signer or ProvenanceSigner()
        self.store = ContextStore()
        self._sigs: dict[int, SignedProvenance] = {}

    def add(self, span: Span) -> Span:
        self.store.add(span)
        self._sigs[span.span_id] = self.signer.sign(span)
        return span

    def extend(self, spans: list[Span]) -> list[Span]:
        for s in spans:
            self.add(s)
        return spans

    def verify_all(self) -> list[int]:
        """Return span ids whose provenance signature does NOT verify."""
        bad = []
        for span in self.store.all():
            sig = self._sigs.get(span.span_id)
            if sig is None or not self.signer.verify(span, sig):
                bad.append(span.span_id)
        return bad

    @property
    def underlying(self):
        return self.store
