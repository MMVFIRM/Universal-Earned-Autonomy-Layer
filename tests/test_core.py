from earned_autonomy.core.models import AuthorityClass, AutonomyLevel
from earned_autonomy.core.recommendations import AutonomyRecommendationEngine
from earned_autonomy.core.models import AgentIdentity, TrustStats
from helpers import earn_clean_approvals, make_agent_with_key, make_cp


def test_new_agent_starts_observe_only():
    cp = make_cp()
    make_agent_with_key(cp)
    agent = cp.store.get_agent("lead_finder")
    assert agent.autonomy_for("sales_lead_generation", AuthorityClass.MODIFY_INTERNAL_RECORD) == AutonomyLevel.OBSERVE_ONLY


def test_sampling_then_conditional_thresholds():
    eng = AutonomyRecommendationEngine()
    agent = AgentIdentity(agent_id="a", name="a", owner_id="o", purpose="p")

    s20 = TrustStats(agent_id="a", workflow_id="w",
                     authority_class=AuthorityClass.MODIFY_INTERNAL_RECORD, clean_approvals=20)
    assert eng.recommend(agent, s20).recommended_level == AutonomyLevel.EXECUTE_WITH_SAMPLING

    s30 = TrustStats(agent_id="a", workflow_id="w",
                     authority_class=AuthorityClass.MODIFY_INTERNAL_RECORD, clean_approvals=30)
    assert eng.recommend(agent, s30).recommended_level == AutonomyLevel.CONDITIONAL_AUTONOMY


def test_full_earn_cycle_produces_recommendation():
    cp = make_cp()
    kp = make_agent_with_key(cp)
    earn_clean_approvals(cp, kp, 30)
    rec = cp.recommend_for("lead_finder", "sales_lead_generation", AuthorityClass.MODIFY_INTERNAL_RECORD)
    assert rec.recommended_level.value >= AutonomyLevel.EXECUTE_WITH_SAMPLING.value
    assert rec.proposed_rule is not None


def test_incident_blocks_recommendation():
    cp = make_cp()
    kp = make_agent_with_key(cp)
    earn_clean_approvals(cp, kp, 30)
    cp.record_incident("lead_finder", "sales_lead_generation",
                       AuthorityClass.MODIFY_INTERNAL_RECORD, reason="bad", actor_id="mgr")
    rec = cp.recommend_for("lead_finder", "sales_lead_generation", AuthorityClass.MODIFY_INTERNAL_RECORD)
    assert rec.recommended_level.value <= AutonomyLevel.EXECUTE_WITH_APPROVAL.value
