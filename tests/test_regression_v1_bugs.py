"""Regression tests: one per v1 defect from the audit. Each proves the fix.

Defect numbering matches the v1 critique. These are the load-bearing tests —
if any fails, a v1 vulnerability has regressed.
"""
from __future__ import annotations

import pytest

from earned_autonomy.core import (
    AuthenticationError,
    ControlPlaneError,
    SeparationOfDutiesError,
)
from earned_autonomy.core.models import (
    AgentIdentity,
    ApprovalDecision,
    ApprovalOutcome,
    AuthorityClass,
    AutonomyLevel,
    DelegationRule,
    TrustStats,
)
from earned_autonomy.core.ontology import autonomy_ceiling_for
from earned_autonomy.core.policy import PolicyEngine
from earned_autonomy.core.recommendations import AutonomyRecommendationEngine
from earned_autonomy.crypto import generate_keypair, sign

from helpers import make_agent_with_key, make_cp, signed_event


# Defect 1: control plane was advisory; nothing stopped execution.
def test_defect1_no_token_means_no_execution():
    from earned_autonomy.enforcement import PolicyEnforcementPoint
    cp = make_cp()
    kp = make_agent_with_key(cp)
    pep = PolicyEnforcementPoint(cp.capability_service)
    ev = signed_event(kp)  # new agent, state change -> approval_required, no token
    packet = cp.propose_event(ev)
    assert packet["policy_decision"]["status"] == "approval_required"
    assert packet["capability_token"] is None
    executed = {"ran": False}
    result = pep.execute(
        token=None, agent_id=ev.agent_id, workflow_id=ev.workflow_id,
        authority_class=ev.authority_requested, action=lambda: executed.update(ran=True),
    )
    assert result.allowed is False
    assert executed["ran"] is False  # the side effect never happened


# Defect 2: incident downgrade was bypassed by a still-active delegation rule.
def test_defect2_incident_deactivates_delegation_rule():
    cp = make_cp()
    kp = make_agent_with_key(cp)
    # Enact a rule granting conditional autonomy on internal record changes.
    rule = DelegationRule(
        rule_name="auto internal updates",
        workflow_id="sales_lead_generation",
        agent_id="lead_finder",
        authority_class=AuthorityClass.MODIFY_INTERNAL_RECORD,
        autonomy_level=AutonomyLevel.CONDITIONAL_AUTONOMY,
        conditions={"evidence_required": True},
    )
    cp.approve_delegation_rule(rule, approver_id="sales_rep_01")

    ev = signed_event(kp, metadata={"evidence_required": True})
    before = cp.propose_event(ev)
    assert before["policy_decision"]["status"] == "allowed"  # rule grants it

    cp.record_incident(
        "lead_finder", "sales_lead_generation", AuthorityClass.MODIFY_INTERNAL_RECORD,
        reason="agent corrupted a record", actor_id="sales_manager",
    )
    ev2 = signed_event(kp, metadata={"evidence_required": True})
    after = cp.propose_event(ev2)
    # The v1 bug: this would still be "allowed" via the matching rule.
    assert after["policy_decision"]["status"] == "approval_required"


# Defect 3: requires_approval_if was dead code.
def test_defect3_requires_approval_if_is_enforced():
    cp = make_cp()
    kp = make_agent_with_key(cp)
    rule = DelegationRule(
        rule_name="conditional internal updates",
        workflow_id="sales_lead_generation",
        agent_id="lead_finder",
        authority_class=AuthorityClass.MODIFY_INTERNAL_RECORD,
        autonomy_level=AutonomyLevel.CONDITIONAL_AUTONOMY,
        conditions={"evidence_required": True},
        requires_approval_if=["low_confidence"],
    )
    cp.approve_delegation_rule(rule, approver_id="sales_rep_01")

    low = signed_event(kp, confidence=0.3, metadata={"evidence_required": True})
    packet = cp.propose_event(low)
    assert packet["policy_decision"]["status"] == "approval_required"
    assert "low_confidence" in packet["policy_decision"]["triggered_guards"]

    high = signed_event(kp, confidence=0.95, metadata={"evidence_required": True})
    assert cp.propose_event(high)["policy_decision"]["status"] == "allowed"


# Defect 4: no agent authentication; identity self-asserted.
def test_defect4_unsigned_unknown_and_forged_rejected():
    cp = make_cp()
    kp = make_agent_with_key(cp)

    unsigned = signed_event(kp)
    unsigned.signature = None
    with pytest.raises(AuthenticationError):
        cp.propose_event(unsigned)

    forged = signed_event(kp)
    other = generate_keypair()
    forged.signature = sign(other.private_key_hex, forged.signing_payload())
    with pytest.raises(AuthenticationError):
        cp.propose_event(forged)

    unknown = signed_event(kp, agent_id="ghost")
    unknown.signature = sign(kp.private_key_hex, unknown.signing_payload())
    with pytest.raises(AuthenticationError):
        cp.propose_event(unknown)


# Defect 5: trust gameable by replaying decisions against one event.
def test_defect5_replay_does_not_inflate_trust():
    cp = make_cp()
    kp = make_agent_with_key(cp)
    ev = signed_event(kp)
    cp.propose_event(ev)
    decision = ApprovalDecision(
        event_id=ev.event_id, approver_id="sales_manager",
        approver_role="manager", outcome=ApprovalOutcome.APPROVED,
    )
    cp.submit_decision(decision)
    with pytest.raises(ControlPlaneError):
        cp.submit_decision(decision)  # same event -> replay rejected

    stats = cp.delegation_memory.get(
        "lead_finder", "sales_lead_generation", AuthorityClass.MODIFY_INTERNAL_RECORD
    )
    assert stats.clean_approvals == 1
    assert stats.total_decisions == 1

    # Event nonce replay is also blocked at proposal time.
    with pytest.raises(AuthenticationError):
        cp.propose_event(ev)


# Defect 6: declared authority never bound to the actual action.
def test_defect6_token_scope_bound_to_actual_action():
    from earned_autonomy.enforcement import PolicyEnforcementPoint
    cp = make_cp()
    make_agent_with_key(cp)
    pep = PolicyEnforcementPoint(cp.capability_service)
    token = cp.capability_service.mint(
        agent_id="lead_finder", workflow_id="sales_lead_generation",
        authority_class=AuthorityClass.MODIFY_INTERNAL_RECORD,
        conditions={}, ttl_seconds=300, single_use=True,
    )
    # Agent tries to use an internal-record token to DELETE data.
    result = pep.execute(
        token=token, agent_id="lead_finder", workflow_id="sales_lead_generation",
        authority_class=AuthorityClass.DELETE_DATA, action=lambda: "deleted",
    )
    assert result.allowed is False
    assert "authority class mismatch" in result.reason


# Defect 7: default autonomy was EXECUTE_WITH_APPROVAL (3), not OBSERVE_ONLY (0).
def test_defect7_default_is_observe_only_and_observation_is_free():
    cp = make_cp()
    kp = make_agent_with_key(cp)
    agent = cp.store.get_agent("lead_finder")
    assert agent.autonomy_for("sales_lead_generation", AuthorityClass.MODIFY_INTERNAL_RECORD) == AutonomyLevel.OBSERVE_ONLY

    observe = signed_event(
        kp, authority=AuthorityClass.OBSERVE, requires_execution=False,
        intent="Read the public attorney directory.",
    )
    packet = cp.propose_event(observe)
    assert packet["policy_decision"]["status"] == "allowed"  # observation needs no approval


# Defect 8: no risk -> max-autonomy ceiling; irreversible classes auto-delegable.
def test_defect8_risk_ceiling_caps_autonomy():
    assert autonomy_ceiling_for(AuthorityClass.TRANSFER_VALUE) == AutonomyLevel.EXECUTE_WITH_APPROVAL
    assert autonomy_ceiling_for(AuthorityClass.DELETE_DATA) == AutonomyLevel.EXECUTE_WITH_APPROVAL
    assert autonomy_ceiling_for(AuthorityClass.OBSERVE) == AutonomyLevel.DELEGATED_AUTHORITY

    cp = make_cp()
    make_agent_with_key(cp)
    over_ceiling = DelegationRule(
        rule_name="reckless", workflow_id="sales_lead_generation", agent_id="lead_finder",
        authority_class=AuthorityClass.TRANSFER_VALUE, autonomy_level=AutonomyLevel.CONDITIONAL_AUTONOMY,
    )
    with pytest.raises(ControlPlaneError):
        cp.approve_delegation_rule(over_ceiling, approver_id="finance_admin")

    # Even with massive clean history, the recommender never exceeds the ceiling.
    stats = TrustStats(
        agent_id="lead_finder", workflow_id="w", authority_class=AuthorityClass.TRANSFER_VALUE,
        clean_approvals=10000,
    )
    agent = AgentIdentity(agent_id="lead_finder", name="x", owner_id="o", purpose="p")
    rec = AutonomyRecommendationEngine().recommend(agent, stats)
    assert rec.recommended_level.value <= AutonomyLevel.EXECUTE_WITH_APPROVAL.value


# Defect 9: owner could approve their own agent (no separation of duties).
def test_defect9_separation_of_duties_enforced():
    cp = make_cp()
    kp = make_agent_with_key(cp, owner_id="rep_self")
    ev = signed_event(kp, owner_id="rep_self", authority=AuthorityClass.OFFER_PRICING_OR_DISCOUNT,
                      intent="Offer a 15% discount.")
    cp.propose_event(ev)
    with pytest.raises(SeparationOfDutiesError):
        cp.submit_decision(ApprovalDecision(
            event_id=ev.event_id, approver_id="rep_self", outcome=ApprovalOutcome.APPROVED,
        ))


# Defect 10: MODIFIED_AND_APPROVED was counted as a clean success.
def test_defect10_modifications_do_not_count_as_clean():
    cp = make_cp()
    kp = make_agent_with_key(cp)
    for _ in range(30):
        ev = signed_event(kp)
        cp.propose_event(ev)
        cp.submit_decision(ApprovalDecision(
            event_id=ev.event_id, approver_id="sales_manager", approver_role="manager",
            outcome=ApprovalOutcome.MODIFIED_AND_APPROVED,
        ))
    stats = cp.delegation_memory.get(
        "lead_finder", "sales_lead_generation", AuthorityClass.MODIFY_INTERNAL_RECORD
    )
    assert stats.clean_approvals == 0
    assert stats.modified_approvals == 30
    assert stats.clean_approval_lower_bound == 0.0
    rec = cp.recommend_for("lead_finder", "sales_lead_generation", AuthorityClass.MODIFY_INTERNAL_RECORD)
    assert rec.recommended_level == AutonomyLevel.OBSERVE_ONLY  # no autonomy earned by edits


# Defect 11: ladder levels 5/6/7 collapsed to identical behavior.
def test_defect11_ladder_levels_have_distinct_behavior():
    engine = PolicyEngine()
    from earned_autonomy.core.ontology import consequences_for
    from earned_autonomy.core.models import RiskLevel

    def evaluate(level, anomaly):
        ev = signed_event(generate_keypair(), authority=AuthorityClass.MODIFY_INTERNAL_RECORD,
                          metadata={"anomaly": anomaly} if anomaly else {})
        return engine.evaluate(
            event=ev, current_autonomy_level=level,
            consequence_classes=consequences_for(AuthorityClass.MODIFY_INTERNAL_RECORD),
            classifier_risk=RiskLevel.LOW,
        )

    # Level 5 ignores anomaly metadata; 6 escalates on it; 7 adds sampling.
    assert evaluate(AutonomyLevel.CONDITIONAL_AUTONOMY, anomaly=True).status.value == "allowed"
    assert evaluate(AutonomyLevel.EXCEPTION_BASED_SUPERVISION, anomaly=True).status.value == "escalate"
    assert evaluate(AutonomyLevel.EXCEPTION_BASED_SUPERVISION, anomaly=False).status.value == "allowed"
    d7 = evaluate(AutonomyLevel.DELEGATED_AUTHORITY, anomaly=False)
    d6 = evaluate(AutonomyLevel.EXCEPTION_BASED_SUPERVISION, anomaly=False)
    assert d7.sample_rate > 0 and d6.sample_rate == 0  # 7 carries periodic attestation


# Defect 11b: keyword classifier substring false-positives and bypasses.
def test_defect_classifier_word_boundaries():
    from earned_autonomy.core.classifier import RuleBasedClassifier
    from earned_autonomy.core.models import RiskLevel
    clf = RuleBasedClassifier()

    benign = signed_event(generate_keypair(), authority=AuthorityClass.OBSERVE,
                          requires_execution=False, intent="Run an accessibility review of the site.")
    _, risk, _ = clf.classify(benign)
    assert risk == RiskLevel.LOW  # 'accessibility' no longer trips on 'access'

    dangerous = signed_event(generate_keypair(), authority=AuthorityClass.MODIFY_INTERNAL_RECORD,
                             intent="Purge the staging records and drop the temp table.")
    _, risk2, _ = clf.classify(dangerous)
    assert risk2 == RiskLevel.HIGH  # 'purge'/'drop' bypass words are caught
