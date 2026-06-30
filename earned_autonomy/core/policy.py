from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional

from .conditions import evaluate_guards
from .models import (
    AuthorityClass,
    AutonomyLevel,
    AutonomyStatus,
    DelegationRule,
    PolicyDecision,
    RiskLevel,
    WorkflowEvent,
)
from .ontology import (
    autonomy_ceiling_for,
    is_non_state,
    max_risk,
)


@dataclass
class BoundaryRule:
    name: str
    authority_classes: List[AuthorityClass] = field(default_factory=list)
    metadata_conditions: Dict[str, Any] = field(default_factory=dict)
    status: AutonomyStatus = AutonomyStatus.APPROVAL_REQUIRED
    risk_level: RiskLevel = RiskLevel.MEDIUM
    reason: str = "Policy boundary matched"
    required_approver_role: Optional[str] = None

    def matches(self, event: WorkflowEvent) -> bool:
        if self.authority_classes and event.authority_requested not in self.authority_classes:
            return False
        for key, expected in self.metadata_conditions.items():
            if event.metadata.get(key) != expected:
                return False
        return True


class PolicyEngine:
    """Deterministic policy engine.

    Order of evaluation (each step can only make the outcome MORE restrictive):
      1. Hard boundary rules (block / escalate / always-approve).
      2. Compute the autonomy ceiling for the authority class.
      3. Take the lower of (earned level, delegation-rule level) and the ceiling.
      4. Evaluate requires_approval_if guards on any matching delegation rule.
      5. Map the resulting effective level to a status, with distinct behavior
         for each rung of the ladder.
    """

    def __init__(self, boundary_rules: Optional[Iterable[BoundaryRule]] = None):
        self.boundary_rules = list(boundary_rules if boundary_rules is not None else default_boundary_rules())

    def evaluate(
        self,
        event: WorkflowEvent,
        current_autonomy_level: AutonomyLevel,
        consequence_classes,
        classifier_risk: RiskLevel,
        matching_delegation_rule: Optional[DelegationRule] = None,
    ) -> PolicyDecision:
        ceiling = autonomy_ceiling_for(event.authority_requested)

        # 1. Hard boundaries first. These override all trust history.
        for rule in self.boundary_rules:
            if rule.matches(event):
                return PolicyDecision(
                    status=rule.status,
                    risk_level=max_risk(classifier_risk, rule.risk_level),
                    consequence_classes=consequence_classes,
                    reason=rule.reason,
                    policy_name=rule.name,
                    required_approver_role=rule.required_approver_role,
                    autonomy_ceiling=int(ceiling.value),
                )

        # 2-3. Effective level = min(what the agent may use here, the ceiling).
        rule_level = matching_delegation_rule.autonomy_level if matching_delegation_rule else None
        candidate = current_autonomy_level
        source = "earned autonomy level"
        policy_name = None
        if rule_level is not None and rule_level.value > candidate.value:
            candidate = rule_level
            source = "delegation rule"
            policy_name = matching_delegation_rule.rule_name

        effective = AutonomyLevel(min(candidate.value, ceiling.value))
        ceiling_clamped = effective.value < candidate.value

        # 4. Guard evaluation: if a delegation rule is the thing granting
        #    autonomy, its requires_approval_if predicates must all be clear.
        triggered: List[str] = []
        if source == "delegation rule" and matching_delegation_rule is not None:
            triggered = evaluate_guards(matching_delegation_rule.requires_approval_if, event)
            if triggered:
                return PolicyDecision(
                    status=AutonomyStatus.APPROVAL_REQUIRED,
                    risk_level=classifier_risk,
                    consequence_classes=consequence_classes,
                    reason=f"Delegation rule guard(s) fired: {', '.join(triggered)}",
                    policy_name=policy_name,
                    autonomy_ceiling=int(ceiling.value),
                    triggered_guards=triggered,
                )

        return self._status_for_level(
            event=event,
            effective=effective,
            risk=classifier_risk,
            consequence_classes=consequence_classes,
            source=source,
            policy_name=policy_name,
            ceiling=ceiling,
            ceiling_clamped=ceiling_clamped,
            matching_delegation_rule=matching_delegation_rule,
        )

    def _status_for_level(
        self,
        event: WorkflowEvent,
        effective: AutonomyLevel,
        risk: RiskLevel,
        consequence_classes,
        source: str,
        policy_name: Optional[str],
        ceiling: AutonomyLevel,
        ceiling_clamped: bool,
        matching_delegation_rule: Optional[DelegationRule],
    ) -> PolicyDecision:
        non_state = is_non_state(event.authority_requested)
        clamp_note = " (clamped by risk ceiling)" if ceiling_clamped else ""

        def decision(status: AutonomyStatus, reason: str, sample_rate: float = 0.0) -> PolicyDecision:
            return PolicyDecision(
                status=status,
                risk_level=risk,
                consequence_classes=consequence_classes,
                reason=reason + clamp_note,
                policy_name=policy_name,
                sample_rate=sample_rate,
                autonomy_ceiling=int(ceiling.value),
            )

        # Non-state authorities (reads, scoring, drafting) are not execution and
        # are allowed once the agent is at the matching rung — no human gate for
        # looking at data.
        if non_state and not event.requires_execution:
            if effective.value >= AutonomyLevel.OBSERVE_ONLY.value:
                return decision(AutonomyStatus.ALLOWED, "Non-state action permitted at current autonomy.")

        rule_sample = matching_delegation_rule.sample_rate if matching_delegation_rule else 0.0

        # Distinct semantics per rung:
        if effective == AutonomyLevel.DELEGATED_AUTHORITY:
            # Broadest autonomy, but periodic attestation: every Nth action is
            # sampled for review, and anomalies still escalate.
            if event.metadata.get("anomaly") is True:
                return decision(AutonomyStatus.ESCALATE, "Delegated authority but anomaly flag set.")
            return decision(
                AutonomyStatus.ALLOWED,
                "Delegated authority within approved envelope (periodic attestation).",
                sample_rate=max(rule_sample, 0.05),
            )

        if effective == AutonomyLevel.EXCEPTION_BASED_SUPERVISION:
            # Allowed unless an exception/anomaly signal is present, in which
            # case it escalates rather than silently proceeding.
            if event.metadata.get("anomaly") is True:
                return decision(AutonomyStatus.ESCALATE, "Exception-based supervision caught an anomaly.")
            return decision(AutonomyStatus.ALLOWED, "Exception-based supervision: no anomaly detected.")

        if effective == AutonomyLevel.CONDITIONAL_AUTONOMY:
            return decision(AutonomyStatus.ALLOWED, "Conditional autonomy: action inside approved policy envelope.")

        if effective == AutonomyLevel.EXECUTE_WITH_SAMPLING:
            return decision(
                AutonomyStatus.SAMPLE_REVIEW,
                "Execution allowed with human sample review.",
                sample_rate=rule_sample or 0.2,
            )

        if effective.value <= AutonomyLevel.DRAFT.value:
            if event.requires_execution:
                return decision(AutonomyStatus.APPROVAL_REQUIRED, "Agent has not earned execution authority.")
            return decision(AutonomyStatus.ALLOWED, "Preparatory (non-execution) work permitted.")

        # EXECUTE_WITH_APPROVAL and any fallthrough.
        return decision(AutonomyStatus.APPROVAL_REQUIRED, "Current autonomy level requires approval for execution.")


def default_boundary_rules() -> List[BoundaryRule]:
    return [
        BoundaryRule(
            name="Block legal position changes",
            authority_classes=[AuthorityClass.CHANGE_LEGAL_POSITION, AuthorityClass.BIND_ORGANIZATION],
            status=AutonomyStatus.BLOCKED,
            risk_level=RiskLevel.CRITICAL,
            reason="Legal/binding authority is blocked unless handled by a specialized enterprise policy.",
            required_approver_role="legal_admin",
        ),
        BoundaryRule(
            name="Value transfer and spend require escalation",
            authority_classes=[AuthorityClass.TRANSFER_VALUE, AuthorityClass.SPEND_MONEY],
            status=AutonomyStatus.ESCALATE,
            risk_level=RiskLevel.CRITICAL,
            reason="Moving or spending money requires escalation and named human accountability.",
            required_approver_role="finance_admin",
        ),
        BoundaryRule(
            name="Pricing and discounts require approval",
            authority_classes=[AuthorityClass.OFFER_PRICING_OR_DISCOUNT, AuthorityClass.COMMIT_COMMERCIAL_POSITION],
            status=AutonomyStatus.APPROVAL_REQUIRED,
            risk_level=RiskLevel.HIGH,
            reason="Pricing, discount, or commercial commitment requires human accountability.",
            required_approver_role="commercial_owner",
        ),
        BoundaryRule(
            name="Production and deletion require escalation",
            authority_classes=[AuthorityClass.DELETE_DATA, AuthorityClass.MODIFY_PRODUCTION_SYSTEM],
            status=AutonomyStatus.ESCALATE,
            risk_level=RiskLevel.CRITICAL,
            reason="Destructive or production-impacting actions require escalation.",
            required_approver_role="system_admin",
        ),
        BoundaryRule(
            name="Access changes require approval",
            authority_classes=[AuthorityClass.GRANT_ACCESS, AuthorityClass.REVOKE_ACCESS],
            status=AutonomyStatus.APPROVAL_REQUIRED,
            risk_level=RiskLevel.HIGH,
            reason="Access authority requires human approval.",
            required_approver_role="security_admin",
        ),
    ]
