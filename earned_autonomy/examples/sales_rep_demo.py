"""Guardrail-focused scenario for the flagship sales-rep use case.

Run: python examples/sales_rep_demo.py

Demonstrates the boundaries that protect the enterprise regardless of how much
trust an agent has earned:
  * Observation is free (no approval) at the default Observe-Only level.
  * Pricing/discount actions require approval AND a second approver (the owner
    cannot rubber-stamp their own agent).
  * Value transfer escalates and can never be auto-delegated (risk ceiling).
"""
from __future__ import annotations

from earned_autonomy.core import (
    EarnedAutonomyControlPlane, ControlPlaneConfig, SeparationOfDutiesError,
)
from earned_autonomy.core.models import (
    AgentIdentity, ApprovalDecision, ApprovalOutcome, AuthorityClass, EvidenceItem,
)
from earned_autonomy.core.ontology import autonomy_ceiling_for
from earned_autonomy.enforcement import AgentClient, PolicyEnforcementPoint
from earned_autonomy.crypto import generate_keypair

WORKFLOW = "sales_lead_generation"


def main():
    cp = EarnedAutonomyControlPlane(config=ControlPlaneConfig(strict_mode=True))
    pep = PolicyEnforcementPoint(cp.capability_service)
    kp = generate_keypair()
    cp.register_agent(AgentIdentity(
        agent_id="sdr_bot", name="SDR Bot", owner_id="rep_dana",
        purpose="Outbound sales development.", public_key_hex=kp.public_key_hex,
        approved_workflows=[WORKFLOW],
    ))
    agent = AgentClient("sdr_bot", "rep_dana", kp, cp, pep)

    print("Observation (read public data) at Observe-Only:")
    obs = agent.build_event(WORKFLOW, "research", "Read the firm's public bio page.",
                            AuthorityClass.OBSERVE, "Notes captured.", "No state change.",
                            confidence=0.9, requires_execution=False)
    print("  ->", cp.propose_event(obs)["policy_decision"]["status"])

    print("\nOffer a discount (pricing authority):")
    disc = agent.build_event(WORKFLOW, "negotiation", "Offer a 15% introductory discount.",
                             AuthorityClass.OFFER_PRICING_OR_DISCOUNT, "Discount quoted.",
                             "Customer-facing financial commitment.", confidence=0.9,
                             evidence=[EvidenceItem(source="crm", claim="Q3 promo approved band is 0-20%.")])
    pkt = cp.propose_event(disc)
    print("  decision ->", pkt["policy_decision"]["status"],
          "| required approver role:", pkt["policy_decision"]["required_approver_role"])

    print("  owner tries to approve their own agent (separation of duties):")
    try:
        cp.submit_decision(ApprovalDecision(event_id=disc.event_id, approver_id="rep_dana",
                                            outcome=ApprovalOutcome.APPROVED))
    except SeparationOfDutiesError as exc:
        print("   blocked:", exc)
    print("  a commercial owner (different principal) approves:")
    out = cp.submit_decision(ApprovalDecision(event_id=disc.event_id, approver_id="mgr_lee",
                                              approver_role="commercial_owner",
                                              outcome=ApprovalOutcome.APPROVED))
    print("   recorded; clean approvals now:", out["trust_stats"]["clean_approvals"])

    print("\nValue transfer can never be auto-delegated:")
    print("  ceiling for transfer_value:", autonomy_ceiling_for(AuthorityClass.TRANSFER_VALUE).label)
    wire = agent.build_event(WORKFLOW, "closing", "Wire the signing bonus to the client.",
                             AuthorityClass.TRANSFER_VALUE, "Funds transferred.",
                             "Irreversible money movement.", confidence=0.99)
    print("  decision ->", cp.propose_event(wire)["policy_decision"]["status"])


if __name__ == "__main__":
    main()
