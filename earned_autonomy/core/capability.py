from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional
from uuid import uuid4

from ..crypto import sign, verify
from .capability_store import CapabilityStateStore, InMemoryCapabilityStore
from .models import AuthorityClass, CapabilityToken, new_id
from .ontology import consequence_rank


@dataclass
class VerificationResult:
    ok: bool
    reason: str
    token_id: Optional[str] = None


class CapabilityService:
    """Mints and verifies capability tokens — the bridge from decision to action.

    A token is a signed, short-lived, scoped grant. The control plane mints one
    only when a decision resolves to ALLOWED. The Policy Enforcement Point calls
    `verify_for_action` with the *actual* action the agent is about to take, and
    the service checks that action against the token scope. This is what closes
    the v1 gap where the agent's self-declared authority was never bound to what
    it actually did: the PEP compares the real action to the signed grant.

    Consumption and revocation state live in a pluggable `CapabilityStateStore`.
    The default in-memory store is single-process; a SqlCapabilityStore makes the
    once-only (single_use) guarantee hold across replicas by making consume an
    atomic, shared operation. See core/capability_store.py.
    """

    def __init__(
        self,
        issuer_private_key_hex: str,
        issuer_public_key_hex: str,
        issuer: str = "control-plane",
        state_store: Optional[CapabilityStateStore] = None,
    ):
        self._private = issuer_private_key_hex
        self._public = issuer_public_key_hex
        self.issuer = issuer
        self.state: CapabilityStateStore = state_store or InMemoryCapabilityStore()

    def mint(
        self,
        agent_id: str,
        workflow_id: str,
        authority_class: AuthorityClass,
        conditions: Dict[str, Any],
        ttl_seconds: int,
        single_use: bool,
        event_id: Optional[str] = None,
    ) -> CapabilityToken:
        now = datetime.now(timezone.utc)
        expires_at = (now + timedelta(seconds=ttl_seconds)).isoformat()
        token = CapabilityToken(
            token_id=new_id("cap"),
            agent_id=agent_id,
            workflow_id=workflow_id,
            authority_class=authority_class,
            max_consequence_rank=consequence_rank(authority_class),
            conditions=conditions,
            issued_at=now.isoformat(),
            expires_at=expires_at,
            nonce=uuid4().hex,
            single_use=single_use,
            issuer=self.issuer,
            event_id=event_id,
        )
        token.signature = sign(self._private, token.signing_payload())
        self.state.record_issued(
            token.token_id, agent_id, workflow_id, authority_class.value, expires_at
        )
        return token

    def revoke(self, token_id: str) -> None:
        self.state.revoke(token_id)

    def revoke_scope(self, agent_id: str, workflow_id: str, authority_class: AuthorityClass) -> int:
        """Revoke all still-issued tokens matching a scope.

        Used when an incident or manual rule revocation happens after a token was
        minted but before it was consumed. Backed by the shared state store, so a
        revocation on one replica is visible to all of them.
        """
        return self.state.revoke_scope(agent_id, workflow_id, authority_class.value)

    def is_revoked(self, token_id: str) -> bool:
        return self.state.is_revoked(token_id)

    def purge_expired(self, now_iso: Optional[str] = None) -> int:
        """Drop bookkeeping rows for expired tokens. Safe because verify rejects
        on expiry before consume; an expired token can never be consumed. Run
        periodically to bound storage growth."""
        return self.state.purge_expired(now_iso)

    def verify_for_action(
        self,
        token: CapabilityToken,
        action_agent_id: str,
        action_workflow_id: str,
        action_authority_class: AuthorityClass,
        action_context: Optional[Dict[str, Any]] = None,
    ) -> VerificationResult:
        action_context = action_context or {}

        if token.signature is None or not verify(self._public, token.signing_payload(), token.signature):
            return VerificationResult(False, "invalid token signature", token.token_id)

        if self.is_revoked(token.token_id):
            return VerificationResult(False, "token revoked", token.token_id)

        try:
            expires = datetime.fromisoformat(token.expires_at)
        except ValueError:
            return VerificationResult(False, "malformed expiry", token.token_id)
        if datetime.now(timezone.utc) >= expires:
            return VerificationResult(False, "token expired", token.token_id)

        # The crux: the ACTUAL action must fall within the token's scope. These
        # are pure reads with no side effect, so they run before consumption.
        if action_agent_id != token.agent_id:
            return VerificationResult(False, "agent mismatch", token.token_id)
        if action_workflow_id != token.workflow_id:
            return VerificationResult(False, "workflow mismatch", token.token_id)
        if action_authority_class != token.authority_class:
            return VerificationResult(False, "authority class mismatch", token.token_id)

        action_rank = action_context.get("consequence_rank")
        if action_rank is not None and action_rank > token.max_consequence_rank:
            return VerificationResult(False, "action consequence exceeds token scope", token.token_id)

        for key, expected in token.conditions.items():
            actual = action_context.get(key)
            if isinstance(expected, dict):
                lo, hi = expected.get("min"), expected.get("max")
                if lo is not None and (actual is None or actual < lo):
                    return VerificationResult(False, f"condition {key} below min", token.token_id)
                if hi is not None and (actual is None or actual > hi):
                    return VerificationResult(False, f"condition {key} above max", token.token_id)
            elif isinstance(expected, list):
                if actual not in expected:
                    return VerificationResult(False, f"condition {key} not in allowed set", token.token_id)
            else:
                if actual != expected:
                    return VerificationResult(False, f"condition {key} mismatch", token.token_id)

        # Consumption is the final, atomic gate. For single-use tokens the shared
        # store decides exactly one winner across all replicas; a concurrent
        # revoke is honored because try_consume also requires revoked=0.
        if token.single_use:
            if not self.state.try_consume(token.token_id):
                # Lost the race or was revoked between checks. Disambiguate for
                # the caller; either way execution is refused.
                if self.is_revoked(token.token_id):
                    return VerificationResult(False, "token revoked", token.token_id)
                return VerificationResult(False, "single-use token already consumed", token.token_id)

        return VerificationResult(True, "ok", token.token_id)
