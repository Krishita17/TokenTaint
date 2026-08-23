"""Capability-based endorsement + audited declassification.

Blocking a tainted sink is safe but blunt. Real workflows need a controlled way
to say "yes, I -- a trusted principal -- authorize *this specific* action,"
without globally lowering trust. Two classic security paradigms give the right
shape:

  * Object-capability security: authority is an unforgeable, narrowly-scoped
    token you must *present*, not an ambient property. Here a trusted principal
    (the human, or a policy service) mints a capability bound to a single sink
    call -- specific tool + specific arguments -- that expires after one use.

  * Information-flow *declassification / endorsement* (Myers & Liskov): the only
    legitimate way to raise the trust of tainted data is an explicit, logged act
    by an authorized principal. A capability here is exactly a declassification
    receipt: it endorses one tainted action and is recorded in the audit log.

Novelty: capability tokens minted per-action, cryptographically bound to the
*arguments* of an LLM tool call, are how a human-in-the-loop "approve" becomes a
tamper-evident, replay-resistant grant rather than a soft prompt the model could
be tricked into fabricating.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import time
import uuid
from dataclasses import dataclass, field

from .types import ProposedAction, TrustLevel


def _bind(tool_name: str, arguments: dict) -> str:
    """Canonical fingerprint of the exact action being authorized."""
    items = "&".join(f"{k}={arguments[k]}" for k in sorted(arguments))
    return hashlib.sha256(f"{tool_name}?{items}".encode()).hexdigest()


@dataclass
class Capability:
    """A single-use, action-bound grant issued by a trusted principal."""

    cap_id: str
    principal: str            # who authorized it (e.g. "user", "policy:oncall")
    granted_trust: TrustLevel  # the trust this endorsement confers
    action_fingerprint: str    # binds it to one tool + argument set
    signature: str             # HMAC by the harness authority key
    expires_at: float
    spent: bool = False


class CapabilityAuthority:
    """Mints and verifies capabilities. Only trusted code holds an instance.

    The key is infrastructure and never enters the model context, so the model
    cannot forge a grant even if an injection tells it to "issue yourself an
    approval token."
    """

    def __init__(self, key: bytes | None = None, ttl_seconds: float = 300):
        self.key = key or os.urandom(32)
        self.ttl = ttl_seconds
        self._issued: dict[str, Capability] = {}

    def grant(self, action: ProposedAction, principal: str = "user",
              granted_trust: TrustLevel = TrustLevel.TRUSTED) -> Capability:
        cap_id = uuid.uuid4().hex
        fp = _bind(action.tool_name, action.arguments)
        payload = f"{cap_id}|{principal}|{int(granted_trust)}|{fp}".encode()
        sig = hmac.new(self.key, payload, hashlib.sha256).hexdigest()
        cap = Capability(
            cap_id=cap_id, principal=principal, granted_trust=granted_trust,
            action_fingerprint=fp, signature=sig, expires_at=time.time() + self.ttl,
        )
        self._issued[cap_id] = cap
        return cap

    def verify(self, action: ProposedAction, cap: Capability) -> tuple[bool, str]:
        """Return (ok, reason). Checks signature, binding, expiry, single-use."""
        known = self._issued.get(cap.cap_id)
        if known is None:
            return False, "unknown capability"
        if known.spent:
            return False, "capability already spent (replay)"
        if time.time() > known.expires_at:
            return False, "capability expired"
        fp = _bind(action.tool_name, action.arguments)
        if not hmac.compare_digest(fp, cap.action_fingerprint):
            return False, "capability does not match this action's arguments"
        payload = f"{cap.cap_id}|{cap.principal}|{int(cap.granted_trust)}|{cap.action_fingerprint}".encode()
        expected = hmac.new(self.key, payload, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, cap.signature):
            return False, "bad signature"
        return True, "valid"

    def spend(self, cap: Capability) -> None:
        known = self._issued.get(cap.cap_id)
        if known is not None:
            known.spent = True
            cap.spent = True
