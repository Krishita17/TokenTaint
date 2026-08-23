"""Source classifier / provenance labeler.

This is the trusted ingestion boundary. Every piece of content that enters the
agent's context passes through here and comes out as a `Span` with a provenance
label that reflects *where it actually came from* -- assigned by the harness,
never inferred from the bytes. That is the security-critical invariant: content
cannot forge its own origin, because origin is decided by the caller (the code
that fetched/received it), not by parsing the content.
"""
from __future__ import annotations

from .types import DEFAULT_TRUST, Provenance, SourceType, Span, TrustLevel


class Labeler:
    """Attaches provenance to incoming content.

    The API deliberately forces the caller to *name the source*. There is no
    `label(text)` overload that guesses -- guessing is exactly the classifier
    trap TokenTaint is designed to avoid.
    """

    def __init__(self, trust_table: dict | None = None):
        self.trust_table = dict(DEFAULT_TRUST)
        if trust_table:
            self.trust_table.update(trust_table)

    def label(
        self,
        text: str,
        source_type: SourceType,
        origin: str,
        trust_override: TrustLevel | None = None,
        derived_from: list[int] | None = None,
    ) -> Span:
        trust = trust_override if trust_override is not None else self.trust_table[source_type]
        prov = Provenance(source_type=source_type, trust=trust, origin=origin)
        return Span(text=text, provenance=prov, derived_from=derived_from or [])

    # ---- convenience wrappers, one per common source -------------------------

    def from_user(self, text: str) -> Span:
        return self.label(text, SourceType.USER, origin="user")

    def from_system(self, text: str) -> Span:
        return self.label(text, SourceType.SYSTEM, origin="system")

    def from_web(self, text: str, url: str) -> Span:
        return self.label(text, SourceType.WEB_FETCH, origin=url)

    def from_tool(self, text: str, tool_name: str) -> Span:
        return self.label(text, SourceType.TOOL_RESULT, origin=f"tool:{tool_name}")

    def from_document(self, text: str, doc_id: str) -> Span:
        return self.label(text, SourceType.RETRIEVED_DOC, origin=f"doc:{doc_id}")

    def from_email(self, text: str, sender: str) -> Span:
        return self.label(text, SourceType.EMAIL, origin=f"email:{sender}")
