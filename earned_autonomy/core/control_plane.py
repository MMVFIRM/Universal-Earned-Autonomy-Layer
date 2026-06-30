from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from ..crypto import generate_keypair, verify
from ..observability.metrics import GovernanceMetrics
from ..storage import InMemoryStore, Store
from .capability import CapabilityService
from .classifier import Classifier, RuleBasedClassifier
from .ledger import AuditLedger
from .models import (
    AgentIdentity,
    ApprovalDecision,
    ApprovalOutcome,
    AuthorityClass,
    AutonomyLevel,
    AutonomyRecommendation,
    AutonomyStatus,
    CapabilityToken,
    DelegationRule,
    WorkflowEvent,
)
from .ontology import autonomy_ceiling_for, requires_separation_of_duties
from .policy import PolicyEngine
from .recommendations import AutonomyRecommendationEngine
from .trust import DelegationMemory, ReplayError


class ControlPlaneError(Exception):
    pass


class AuthenticationError(ControlPlaneError):
    pass


class SeparationOfDutiesError(ControlPlaneError):
    pass


@dataclass
class ControlPlaneConfig:
    # strict_mode rejects unsigned events and refuses to auto-register unknown
    # agents. This is the production default. Dev/demo can relax it.
    strict_mode: bool = True
    allowed_capability_ttl_seconds: int = 300
    sampled_capability_ttl_seconds: int = 300


class EarnedAutonomyControlPlane:
    """Main orchestration engine for progressive, ENFORCED agent autonomy."""

    def __init__(
        self,
        store: Optional[Store] = None,
        ledger: Optional[AuditLedger] = None,
        classifier: Optional[Classifier] = None,
        policy_engine: Optional[PolicyEngine] = None,
        delegation_memory: Optional[DelegationMemory] = None,
        recommendation_engine: Optional[AutonomyRecommendationEngine] = None,
        capability_service: Optional[CapabilityService] = None,
        config: Optional[ControlPlaneConfig] = None,
        metrics: Optional[GovernanceMetrics] = None,
    ):
        self.config = config or ControlPlaneConfig()
        self.metrics = metrics or GovernanceMetrics()
        self.store = store or InMemoryStore()
        issuer_keys = generate_keypair()
        self.ledger = ledger or AuditLedger(issuer_keys.private_key_hex, issuer_keys.public_key_hex)
        self.classifier = classifier or RuleBasedClassifier()
        self.policy_engine = policy_engine or PolicyEngine()
        self.delegation_memory = delegation_memory or DelegationMemory()
        self.recommendation_engine = recommendation_engine or AutonomyRecommendationEngine()
        self.capability_service = capability_service or CapabilityService(
            issuer_keys.private_key_hex, issuer_keys.public_key_hex
        )

    # --- registration ------------------------------------------------------

    def register_agent(self, agent: AgentIdentity) -> AgentIdentity:
        if self.config.strict_mode and not agent.public_key_hex:
            raise AuthenticationError("strict_mode requires a public_key_hex for agent registration")
        self.store.add_agent(agent)
        self.ledger.append("agent.registered", agent.to_dict(), actor_id=agent.owner_id)
        return agent

    # --- event proposal (the enforcement gate) -----------------------------

    def propose_event(self, event: WorkflowEvent) -> dict:
        agent = self.store.get_agent(event.agent_id)

        # v2 fix: no silent auto-registration of unknown agents. In strict mode
        # an unregistered agent cannot transact at all.
        if agent is None:
            if self.config.strict_mode:
                raise AuthenticationError(f"unknown agent_id: {event.agent_id}")
            agent = AgentIdentity(
                agent_id=event.agent_id, name=event.agent_id, owner_id=event.human_owner_id,
                purpose="Auto-created (non-strict mode)", approved_workflows=[event.workflow_id],
            )
            self.store.add_agent(agent)

        if not agent.active:
            raise AuthenticationError(f"agent {event.agent_id} is deactivated")

        # v2 fix: verify the agent's signature over the event. Identity is a key,
        # not a self-asserted string, so one agent cannot impersonate another.
        if self.config.strict_mode:
            if not event.signature:
                raise AuthenticationError("strict_mode requires a signed event")
            if not agent.public_key_hex or not verify(
                agent.public_key_hex, event.signing_payload(), event.signature
            ):
                raise AuthenticationError("event signature verification failed")

        # v2 fix, hardened in v3: atomic replay protection. claim_nonce is a
        # single check-and-set (unique constraint in SQL / lock in memory), so
        # two replicas cannot both accept the same event.
        if not self.store.claim_nonce(event.agent_id, event.nonce):
            raise AuthenticationError("replayed event nonce")

        self.store.add_event(event)

        consequences, risk, classifier_reasons = self.classifier.classify(event)
        current_level = agent.autonomy_for(event.workflow_id, event.authority_requested)
        matching_rule = self.store.matching_rule(event)

        # Inject context the guard evaluator needs.
        event.metadata.setdefault("_approved_workflows", agent.approved_workflows)

        decision = self.policy_engine.evaluate(
            event=event,
            current_autonomy_level=current_level,
            consequence_classes=consequences,
            classifier_risk=risk,
            matching_delegation_rule=matching_rule,
        )

        # Mint a capability token ONLY when the action may proceed. This is the
        # artifact the agent must present to the Policy Enforcement Point.
        token: Optional[CapabilityToken] = None
        if decision.status in (AutonomyStatus.ALLOWED, AutonomyStatus.SAMPLE_REVIEW):
            ttl = (
                self.config.allowed_capability_ttl_seconds
                if decision.status == AutonomyStatus.ALLOWED
                else self.config.sampled_capability_ttl_seconds
            )
            token = self.capability_service.mint(
                agent_id=event.agent_id,
                workflow_id=event.workflow_id,
                authority_class=event.authority_requested,
                conditions=(matching_rule.conditions if matching_rule else {}),
                ttl_seconds=ttl,
                single_use=True,
                event_id=event.event_id,
            )

        self.metrics.record_decision(decision.status.value)
        packet = {
            "event": event.to_dict(),
            "agent": agent.to_dict(),
            "current_autonomy_level": int(current_level.value),
            "current_autonomy_label": current_level.label,
            "autonomy_ceiling": int(autonomy_ceiling_for(event.authority_requested).value),
            "policy_decision": decision.to_dict(),
            "classifier_reasons": classifier_reasons,
            "matching_delegation_rule": matching_rule.to_dict() if matching_rule else None,
            "capability_token": token.to_dict() if token else None,
            "approval_packet": self._approval_packet(event, decision, classifier_reasons),
        }
        ledger_packet = dict(packet)
        ledger_packet.pop("capability_token", None)  # don't persist secrets in audit body
        self.ledger.append("workflow.event.proposed", ledger_packet, actor_id=event.agent_id)
        return packet

    # --- approval decisions ------------------------------------------------

    def submit_decision(self, decision: ApprovalDecision) -> dict:
        event = self.store.get_event(decision.event_id)
        if event is None:
            raise ControlPlaneError(f"Unknown event_id: {decision.event_id}")

        # Separation of duties: for consequential authority classes, the human
        # approving cannot be the agent's owner approving their own agent.
        if requires_separation_of_duties(event.authority_requested):
            agent = self.store.get_agent(event.agent_id)
            if agent and decision.approver_id == agent.owner_id and decision.outcome in (
                ApprovalOutcome.APPROVED,
                ApprovalOutcome.MODIFIED_AND_APPROVED,
                ApprovalOutcome.CONVERTED_TO_DELEGATION_RULE,
            ):
                raise SeparationOfDutiesError(
                    f"{event.authority_requested.value} requires an approver other than the agent owner"
                )

        try:
            stats = self.delegation_memory.apply_decision(
                event.agent_id, event.workflow_id, event.authority_requested, decision
            )
        except ReplayError as exc:
            raise ControlPlaneError(str(exc)) from exc

        self.ledger.append("approval.decision", decision.to_dict(), actor_id=decision.approver_id)
        recommendation = self.recommend_for(event.agent_id, event.workflow_id, event.authority_requested)
        result = {
            "decision": decision.to_dict(),
            "trust_stats": stats.to_dict(),
            "recommendation": recommendation.to_dict(),
        }
        self.ledger.append("trust.updated", result, actor_id=decision.approver_id)
        return result

    # --- delegation rules --------------------------------------------------

    def approve_delegation_rule(
        self, rule: DelegationRule, approver_id: str, approver_role: Optional[str] = None
    ) -> DelegationRule:
        agent = self.store.get_agent(rule.agent_id)

        # Ceiling enforcement at the source: a rule can never grant above the
        # authority class ceiling, no matter who approves it.
        ceiling = autonomy_ceiling_for(rule.authority_class)
        if rule.autonomy_level.value > ceiling.value:
            raise ControlPlaneError(
                f"rule autonomy {rule.autonomy_level.label} exceeds ceiling {ceiling.label} "
                f"for {rule.authority_class.value}"
            )

        # Separation of duties for consequential classes.
        if requires_separation_of_duties(rule.authority_class) and agent and approver_id == agent.owner_id:
            raise SeparationOfDutiesError(
                f"{rule.authority_class.value} delegation requires an approver other than the agent owner"
            )

        rule.created_by = approver_id
        self.store.add_rule(rule)
        # Note: we deliberately do NOT raise agent.current_autonomy here.
        # Elevated autonomy is granted per-action by a *matching* delegation
        # rule, so the rule's conditions and requires_approval_if guards are
        # evaluated on every action. A standing stored level would bypass them.
        payload = rule.to_dict()
        payload["approved_by"] = approver_id
        payload["approver_role"] = approver_role
        self.ledger.append("delegation_rule.approved", payload, actor_id=approver_id)
        return rule

    def revoke_delegation_rule(self, rule_id: str, actor_id: str, reason: str) -> bool:
        rule = self.store.get_rule(rule_id)
        if not rule:
            return False
        rule.active = False
        rule.revoked_reason = reason
        self.store.add_rule(rule)
        revoked_tokens = self.capability_service.revoke_scope(
            rule.agent_id, rule.workflow_id, rule.authority_class
        )
        self.ledger.append(
            "delegation_rule.revoked",
            {
                "rule_id": rule_id,
                "reason": reason,
                "rule": rule.to_dict(),
                "revoked_capability_tokens": revoked_tokens,
            },
            actor_id=actor_id,
        )
        return True

    # --- incidents (now compose correctly with delegation) -----------------

    def record_incident(
        self, agent_id: str, workflow_id: str, authority_class: AuthorityClass, reason: str, actor_id: str
    ) -> dict:
        stats = self.delegation_memory.record_incident(agent_id, workflow_id, authority_class)
        self.metrics.record_incident()
        agent = self.store.get_agent(agent_id)
        deactivated = []
        if agent:
            agent.incident_count += 1
            current = agent.autonomy_for(workflow_id, authority_class)
            reduced = (
                current
                if current.value <= AutonomyLevel.EXECUTE_WITH_APPROVAL.value
                else AutonomyLevel.EXECUTE_WITH_APPROVAL
            )
            agent.set_autonomy(workflow_id, authority_class, reduced)
            self.store.add_agent(agent)

            # v2 FIX for the composition bug: lowering the agent's level is not
            # enough, because the policy engine consults matching delegation
            # rules first. So we deactivate every matching active rule and revoke
            # any capability already issued under them. After an incident, the
            # next matching action genuinely falls back to approval.
            for rule in self.store.rules_for(agent_id, workflow_id, authority_class.value):
                if rule.active:
                    rule.active = False
                    rule.revoked_reason = f"auto-revoked by incident: {reason}"
                    self.store.add_rule(rule)
                    deactivated.append(rule.rule_id)

        revoked_tokens = self.capability_service.revoke_scope(agent_id, workflow_id, authority_class)

        payload = {
            "agent_id": agent_id,
            "workflow_id": workflow_id,
            "authority_class": authority_class.value,
            "reason": reason,
            "deactivated_rules": deactivated,
            "revoked_capability_tokens": revoked_tokens,
            "trust_stats": stats.to_dict(),
        }
        self.ledger.append("incident.recorded", payload, actor_id=actor_id)
        return payload

    # --- recommendations & views ------------------------------------------

    def recommend_for(
        self, agent_id: str, workflow_id: str, authority_class: AuthorityClass
    ) -> AutonomyRecommendation:
        agent = self.store.get_agent(agent_id)
        if agent is None:
            raise ControlPlaneError(f"Unknown agent_id: {agent_id}")
        stats = self.delegation_memory.get(agent_id, workflow_id, authority_class)
        recommendation = self.recommendation_engine.recommend(agent, stats)
        self.metrics.record_recommendation()
        self.ledger.append("autonomy.recommendation", recommendation.to_dict(), actor_id="system")
        return recommendation

    def autonomy_map(self, agent_id: str) -> dict:
        agent = self.store.get_agent(agent_id)
        if agent is None:
            raise ControlPlaneError(f"Unknown agent_id: {agent_id}")
        relevant = [s for s in self.delegation_memory.all_stats() if s.agent_id == agent_id]
        return {
            "agent": agent.to_dict(),
            "trust_stats": [s.to_dict() for s in relevant],
            "active_rules": [r.to_dict() for r in self.store.all_active_rules_for_agent(agent_id)],
        }

    # --- helpers -----------------------------------------------------------

    @staticmethod
    def _approval_packet(event: WorkflowEvent, decision, classifier_reasons) -> dict:
        return {
            "plain_english_summary": event.intent,
            "requested_authority": event.authority_requested.value,
            "workflow": event.workflow_id,
            "stage": event.workflow_stage,
            "proposed_transition": event.proposed_next_state,
            "expected_effect": event.expected_effect,
            "evidence": [item.to_dict() for item in event.evidence],
            "risk_level": decision.risk_level.value,
            "consequence_classes": [c.value for c in decision.consequence_classes],
            "recommended_status": decision.status.value,
            "autonomy_ceiling": decision.autonomy_ceiling,
            "triggered_guards": decision.triggered_guards,
            "policy_reason": decision.reason,
            "classifier_reasons": classifier_reasons,
            "human_options": [o.value for o in ApprovalOutcome],
        }
