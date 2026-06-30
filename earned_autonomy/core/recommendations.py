from __future__ import annotations

from .models import (
    AgentIdentity,
    AuthorityClass,
    AutonomyLevel,
    AutonomyRecommendation,
    DelegationRule,
    RiskLevel,
    TrustStats,
)
from .ontology import (
    autonomy_ceiling_for,
    base_risk_for,
    requires_separation_of_duties,
)


class AutonomyRecommendationEngine:
    """Suggests delegation changes based on EARNED, statistically-defensible trust.

    v2 changes versus v1:
      * Uses the Wilson lower bound on the clean-approval rate, not the raw point
        estimate, so thin evidence cannot unlock autonomy.
      * Minimum sample size is coupled to consequence severity: riskier classes
        need far more clean history before any relaxation.
      * Never recommends above the authority class's risk ceiling.
      * Flags when a second (separation-of-duties) approver is required to enact
        the recommendation.
      * `confidence` is the Wilson lower bound itself — a real lower-confidence
        bound, not the circular "confidence = approval_rate" of v1.
    """

    # Minimum CLEAN decisions required before each step, scaled by base risk.
    SAMPLES_BY_RISK = {
        RiskLevel.LOW: {"sampling": 8, "conditional": 20, "exception": 50, "delegated": 120},
        RiskLevel.MEDIUM: {"sampling": 20, "conditional": 60, "exception": 150, "delegated": 400},
        RiskLevel.HIGH: {"sampling": 60, "conditional": 200, "exception": 10**9, "delegated": 10**9},
        RiskLevel.CRITICAL: {"sampling": 10**9, "conditional": 10**9, "exception": 10**9, "delegated": 10**9},
    }

    # Required Wilson lower bound on clean-approval rate per target level.
    LB_THRESHOLDS = {
        AutonomyLevel.EXECUTE_WITH_SAMPLING: 0.80,
        AutonomyLevel.CONDITIONAL_AUTONOMY: 0.88,
        AutonomyLevel.EXCEPTION_BASED_SUPERVISION: 0.93,
        AutonomyLevel.DELEGATED_AUTHORITY: 0.95,
    }
    MAX_EDIT_RATE = {
        AutonomyLevel.EXECUTE_WITH_SAMPLING: 0.20,
        AutonomyLevel.CONDITIONAL_AUTONOMY: 0.10,
        AutonomyLevel.EXCEPTION_BASED_SUPERVISION: 0.05,
        AutonomyLevel.DELEGATED_AUTHORITY: 0.03,
    }

    def recommend(self, agent: AgentIdentity, stats: TrustStats) -> AutonomyRecommendation:
        authority = stats.authority_class
        current = agent.autonomy_for(stats.workflow_id, authority)
        ceiling = autonomy_ceiling_for(authority)
        risk = base_risk_for(authority)
        thresholds = self.SAMPLES_BY_RISK[risk]
        lb = stats.clean_approval_lower_bound

        recommended = current
        confidence = lb
        reason = "Not enough clean, distinct evidence to change autonomy."

        # Incidents always pin autonomy down and block relaxation.
        if stats.incidents > 0:
            recommended = min(current, AutonomyLevel.EXECUTE_WITH_APPROVAL, key=lambda x: x.value)
            return self._finalize(agent, stats, current, recommended, 0.99,
                                  "Incident history pins autonomy to approval-required.", ceiling)

        # High rejection rate -> keep approval required.
        if stats.total_decisions >= thresholds["sampling"] and stats.rejection_rate >= 0.25:
            recommended = min(current, AutonomyLevel.EXECUTE_WITH_APPROVAL, key=lambda x: x.value)
            return self._finalize(agent, stats, current, recommended, min(0.9, stats.rejection_rate),
                                  "High rejection rate; approval should remain required.", ceiling)

        # Walk the ladder from the top down; take the highest level the evidence
        # supports that is also at/below the ceiling.
        ladder = [
            (AutonomyLevel.DELEGATED_AUTHORITY, "delegated"),
            (AutonomyLevel.EXCEPTION_BASED_SUPERVISION, "exception"),
            (AutonomyLevel.CONDITIONAL_AUTONOMY, "conditional"),
            (AutonomyLevel.EXECUTE_WITH_SAMPLING, "sampling"),
        ]
        for level, key in ladder:
            if level.value > ceiling.value:
                continue
            if (
                stats.total_decisions >= thresholds[key]
                and lb >= self.LB_THRESHOLDS[level]
                and stats.edit_rate <= self.MAX_EDIT_RATE[level]
            ):
                recommended = max(current, level, key=lambda x: x.value)
                confidence = lb
                reason = (
                    f"Wilson lower bound {lb:.3f} over {stats.total_decisions} clean decisions "
                    f"supports {level.label} (ceiling {ceiling.label})."
                )
                break

        return self._finalize(agent, stats, current, recommended, confidence, reason, ceiling)

    def _finalize(
        self,
        agent: AgentIdentity,
        stats: TrustStats,
        current: AutonomyLevel,
        recommended: AutonomyLevel,
        confidence: float,
        reason: str,
        ceiling: AutonomyLevel,
    ) -> AutonomyRecommendation:
        # Clamp to ceiling defensively.
        recommended = AutonomyLevel(min(recommended.value, ceiling.value))
        proposed_rule = None
        requires_second = False
        if recommended.value > current.value:
            requires_second = requires_separation_of_duties(stats.authority_class)
            proposed_rule = DelegationRule(
                rule_name=f"Suggested {recommended.label} for {stats.agent_id}/{stats.workflow_id}/{stats.authority_class.value}",
                workflow_id=stats.workflow_id,
                agent_id=stats.agent_id,
                authority_class=AuthorityClass(stats.authority_class.value),
                autonomy_level=recommended,
                conditions={"evidence_required": True},
                requires_approval_if=[
                    "missing_source_evidence",
                    "low_confidence",
                    "external_effect",
                    "irreversible",
                    "anomaly_detected",
                    "policy_boundary_matched",
                ],
                sample_rate=0.2 if recommended.value >= AutonomyLevel.EXECUTE_WITH_SAMPLING.value else 0.0,
            )
        return AutonomyRecommendation(
            agent_id=stats.agent_id,
            workflow_id=stats.workflow_id,
            authority_class=stats.authority_class,
            current_level=current,
            recommended_level=recommended,
            confidence=confidence,
            reason=reason,
            autonomy_ceiling=ceiling,
            proposed_rule=proposed_rule,
            requires_second_approver=requires_second,
        )
