"""End-to-end demo of the enforced autonomy lifecycle.

Run: python examples/agent_sdk_demo.py

Shows, in order:
  1. A brand-new agent (Observe-Only) proposing a state change -> approval required, no token.
  2. The agent earning trust over many DISTINCT, signed, human-approved actions.
  3. An admin enacting the earned recommendation as a delegation rule.
  4. The agent now executing autonomously THROUGH the enforcement point, which
     verifies the capability token against the actual action.
  5. An incident auto-revoking the delegation rule, dropping the agent back to
     approval-required on the very next action.
"""
from __future__ import annotations

from earned_autonomy.core import EarnedAutonomyControlPlane, ControlPlaneConfig
from earned_autonomy.core.models import (
    AgentIdentity, ApprovalDecision, ApprovalOutcome, AuthorityClass, EvidenceItem,
)
from earned_autonomy.enforcement import AgentClient, PolicyEnforcementPoint
from earned_autonomy.crypto import generate_keypair

WORKFLOW = "sales_lead_generation"
AUTHORITY = AuthorityClass.MODIFY_INTERNAL_RECORD


def line(msg):
    print(msg)


def main():
    cp = EarnedAutonomyControlPlane(config=ControlPlaneConfig(strict_mode=True))
    pep = PolicyEnforcementPoint(cp.capability_service)
    kp = generate_keypair()

    cp.register_agent(AgentIdentity(
        agent_id="lead_finder", name="Lead Finder", owner_id="sales_rep_01",
        purpose="Qualify inbound law-firm leads.", public_key_hex=kp.public_key_hex,
        approved_workflows=[WORKFLOW],
    ))
    agent = AgentClient("lead_finder", "sales_rep_01", kp, cp, pep)

    def new_event():
        return agent.build_event(
            WORKFLOW, "lead_discovery", "Add a qualified law-firm lead to the CRM.",
            AUTHORITY, "Lead added to prospect queue.", "Internal CRM record created.",
            evidence=[EvidenceItem(source="firm-site", claim="Firm lists 42 attorneys.")],
            confidence=0.95, metadata={"evidence_required": True},
        )

    line("1) New agent proposes a state change:")
    ev = new_event()
    packet = agent.propose(ev)
    line(f"   status={packet['policy_decision']['status']} token={packet['capability_token'] is not None} "
         f"(ceiling={packet['autonomy_ceiling']})")

    line("2) Human approves 30 distinct actions (a manager, not the agent's owner):")
    for _ in range(30):
        e = new_event()
        cp.propose_event(e)
        cp.submit_decision(ApprovalDecision(
            event_id=e.event_id, approver_id="sales_manager", approver_role="manager",
            outcome=ApprovalOutcome.APPROVED,
        ))
    rec = cp.recommend_for("lead_finder", WORKFLOW, AUTHORITY)
    line(f"   recommendation: {rec.recommended_level.label} "
         f"(confidence/Wilson-LB={rec.confidence:.3f}, ceiling={rec.autonomy_ceiling.label})")

    line("3) Admin enacts the recommended delegation rule:")
    cp.approve_delegation_rule(rec.proposed_rule, approver_id="sales_rep_01")
    line(f"   rule active: {rec.proposed_rule.rule_name}")

    line("4) Agent now executes autonomously through the enforcement point:")
    ev2 = new_event()
    packet2 = agent.propose(ev2)
    result = agent.execute(ev2, packet2, action=lambda: "CRM record #8842 written")
    line(f"   decision={packet2['policy_decision']['status']} "
         f"enforced_execution_allowed={result.allowed} output={result.output!r}")

    line("5) An incident is recorded; the rule is auto-revoked:")
    cp.record_incident("lead_finder", WORKFLOW, AUTHORITY,
                       reason="agent wrote a malformed record", actor_id="sales_manager")
    ev3 = new_event()
    packet3 = agent.propose(ev3)
    result3 = agent.execute(ev3, packet3, action=lambda: "should not run")
    line(f"   decision={packet3['policy_decision']['status']} "
         f"enforced_execution_allowed={result3.allowed}")

    line(f"\nAudit ledger verified: {cp.ledger.verify()} over {len(cp.ledger.records())} signed records")


if __name__ == "__main__":
    main()
