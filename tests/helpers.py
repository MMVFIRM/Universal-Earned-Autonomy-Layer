from __future__ import annotations

from earned_autonomy.core import EarnedAutonomyControlPlane, ControlPlaneConfig
from earned_autonomy.core.models import (
    AgentIdentity,
    ApprovalDecision,
    ApprovalOutcome,
    AuthorityClass,
    EvidenceItem,
    WorkflowEvent,
    WorkflowEventType,
)
from earned_autonomy.crypto import KeyPair, generate_keypair, sign


def make_cp(strict: bool = True) -> EarnedAutonomyControlPlane:
    return EarnedAutonomyControlPlane(config=ControlPlaneConfig(strict_mode=strict))


def make_agent_with_key(
    cp: EarnedAutonomyControlPlane,
    agent_id: str = "lead_finder",
    owner_id: str = "sales_rep_01",
    workflows=("sales_lead_generation",),
) -> KeyPair:
    kp = generate_keypair()
    cp.register_agent(
        AgentIdentity(
            agent_id=agent_id,
            name=agent_id,
            owner_id=owner_id,
            purpose="test agent",
            public_key_hex=kp.public_key_hex,
            approved_workflows=list(workflows),
        )
    )
    return kp


def signed_event(
    kp: KeyPair,
    agent_id: str = "lead_finder",
    owner_id: str = "sales_rep_01",
    workflow: str = "sales_lead_generation",
    authority: AuthorityClass = AuthorityClass.MODIFY_INTERNAL_RECORD,
    intent: str = "Add a qualified law-firm lead to the queue.",
    confidence: float = 0.92,
    requires_execution: bool = True,
    with_evidence: bool = True,
    metadata=None,
) -> WorkflowEvent:
    event = WorkflowEvent(
        agent_id=agent_id,
        human_owner_id=owner_id,
        workflow_id=workflow,
        workflow_stage="lead_discovery",
        event_type=WorkflowEventType.PROPOSED_ACTION,
        intent=intent,
        authority_requested=authority,
        proposed_next_state="Lead added to prospect queue.",
        expected_effect="Internal sales record created.",
        evidence=[EvidenceItem(source="web", claim="Firm has 42 attorneys.")] if with_evidence else [],
        confidence=confidence,
        requires_execution=requires_execution,
        metadata=metadata or {},
    )
    event.signature = sign(kp.private_key_hex, event.signing_payload())
    return event


def earn_clean_approvals(
    cp: EarnedAutonomyControlPlane,
    kp: KeyPair,
    n: int,
    authority: AuthorityClass = AuthorityClass.MODIFY_INTERNAL_RECORD,
    approver_id: str = "sales_manager",  # not the owner, to satisfy SoD
    approver_role: str = "manager",
    agent_id: str = "lead_finder",
    owner_id: str = "sales_rep_01",
) -> None:
    """Submit n DISTINCT approved events (each its own nonce/event)."""
    for _ in range(n):
        ev = signed_event(kp, agent_id=agent_id, owner_id=owner_id, authority=authority)
        cp.propose_event(ev)
        cp.submit_decision(
            ApprovalDecision(
                event_id=ev.event_id,
                approver_id=approver_id,
                approver_role=approver_role,
                outcome=ApprovalOutcome.APPROVED,
            )
        )
