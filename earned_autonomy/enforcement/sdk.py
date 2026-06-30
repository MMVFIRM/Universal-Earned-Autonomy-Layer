from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional

from ..core.control_plane import EarnedAutonomyControlPlane
from ..core.models import (
    AuthorityClass,
    CapabilityToken,
    EvidenceItem,
    WorkflowEvent,
    WorkflowEventType,
)
from ..core.ontology import consequence_rank
from ..crypto import KeyPair, sign
from .pep import ExecutionResult, PolicyEnforcementPoint


class AgentClient:
    """Reference agent-side client implementing the runtime contract.

    The agent holds its own Ed25519 private key. It signs every event before
    submission, so the control plane can authenticate it. When a proposal is
    allowed, the client receives a capability token and executes the real action
    through the PEP, which re-checks the token against the action. The agent
    never gets a standing key to a downstream system — only short-lived,
    scoped, single-use capabilities.
    """

    def __init__(
        self,
        agent_id: str,
        human_owner_id: str,
        keypair: KeyPair,
        control_plane: EarnedAutonomyControlPlane,
        pep: PolicyEnforcementPoint,
    ):
        self.agent_id = agent_id
        self.human_owner_id = human_owner_id
        self.keypair = keypair
        self.cp = control_plane
        self.pep = pep

    def build_event(
        self,
        workflow_id: str,
        workflow_stage: str,
        intent: str,
        authority: AuthorityClass,
        proposed_next_state: str,
        expected_effect: str,
        evidence: Optional[List[EvidenceItem]] = None,
        confidence: float = 0.0,
        requires_execution: bool = True,
        metadata: Optional[Dict[str, Any]] = None,
        event_type: WorkflowEventType = WorkflowEventType.PROPOSED_ACTION,
    ) -> WorkflowEvent:
        event = WorkflowEvent(
            agent_id=self.agent_id,
            human_owner_id=self.human_owner_id,
            workflow_id=workflow_id,
            workflow_stage=workflow_stage,
            event_type=event_type,
            intent=intent,
            authority_requested=authority,
            proposed_next_state=proposed_next_state,
            expected_effect=expected_effect,
            evidence=evidence or [],
            confidence=confidence,
            requires_execution=requires_execution,
            metadata=metadata or {},
        )
        event.signature = sign(self.keypair.private_key_hex, event.signing_payload())
        return event

    def propose(self, event: WorkflowEvent) -> dict:
        return self.cp.propose_event(event)

    def execute(
        self,
        event: WorkflowEvent,
        packet: dict,
        action: Callable[[], Any],
        action_context: Optional[Dict[str, Any]] = None,
    ) -> ExecutionResult:
        token_dict = packet.get("capability_token")
        token = _token_from_dict(token_dict) if token_dict else None
        # The action context is what the PEP checks the token's conditions
        # against. It is built from the action's own declared attributes (the
        # event metadata), then any explicit overrides, then the derived
        # consequence rank. The agent cannot widen its own grant this way: the
        # token was minted from the SAME metadata at proposal time, and the PEP
        # independently re-verifies the signature and scope.
        ctx = dict(event.metadata)
        ctx.update(action_context or {})
        ctx.setdefault("consequence_rank", consequence_rank(event.authority_requested))
        return self.pep.execute(
            token=token,
            agent_id=self.agent_id,
            workflow_id=event.workflow_id,
            authority_class=event.authority_requested,
            action=action,
            action_context=ctx,
        )


def _token_from_dict(d: dict) -> CapabilityToken:
    d = dict(d)
    d["authority_class"] = AuthorityClass(d["authority_class"])
    return CapabilityToken(**d)
