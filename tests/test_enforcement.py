from earned_autonomy.core.models import (
    AuthorityClass, AutonomyLevel, DelegationRule, EvidenceItem,
)
from earned_autonomy.enforcement import AgentClient, PolicyEnforcementPoint
from helpers import make_agent_with_key, make_cp


def test_end_to_end_allowed_executes():
    cp = make_cp()
    kp = make_agent_with_key(cp)
    pep = PolicyEnforcementPoint(cp.capability_service)
    client = AgentClient("lead_finder", "sales_rep_01", kp, cp, pep)

    rule = DelegationRule(
        rule_name="auto internal", workflow_id="sales_lead_generation", agent_id="lead_finder",
        authority_class=AuthorityClass.MODIFY_INTERNAL_RECORD,
        autonomy_level=AutonomyLevel.CONDITIONAL_AUTONOMY, conditions={"evidence_required": True},
    )
    cp.approve_delegation_rule(rule, approver_id="sales_rep_01")

    ev = client.build_event(
        "sales_lead_generation", "lead_discovery", "Add a qualified lead.",
        AuthorityClass.MODIFY_INTERNAL_RECORD, "Lead queued.", "Internal record created.",
        evidence=[EvidenceItem(source="web", claim="42 attorneys")], confidence=0.95,
        metadata={"evidence_required": True},
    )
    packet = client.propose(ev)
    assert packet["policy_decision"]["status"] == "allowed"

    ran = {"v": False}
    result = client.execute(ev, packet, action=lambda: ran.update(v=True) or "ok")
    assert result.allowed is True and ran["v"] is True


def test_end_to_end_blocked_does_not_execute():
    cp = make_cp()
    kp = make_agent_with_key(cp)
    pep = PolicyEnforcementPoint(cp.capability_service)
    client = AgentClient("lead_finder", "sales_rep_01", kp, cp, pep)
    ev = client.build_event(
        "sales_lead_generation", "negotiation", "Wire the deposit.",
        AuthorityClass.TRANSFER_VALUE, "Funds moved.", "Money leaves account.",
        confidence=0.99,
    )
    packet = client.propose(ev)
    assert packet["policy_decision"]["status"] in ("escalate", "blocked", "approval_required")
    ran = {"v": False}
    result = client.execute(ev, packet, action=lambda: ran.update(v=True))
    assert result.allowed is False and ran["v"] is False
