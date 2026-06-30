from __future__ import annotations

import math
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4

from ..crypto import canonical_bytes


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid4().hex[:16]}"


class SerializableEnum(str, Enum):
    def __str__(self) -> str:  # pragma: no cover - cosmetic
        return self.value


class WorkflowEventType(SerializableEnum):
    STARTED_WORKFLOW = "agent.started_workflow"
    OBSERVED = "agent.observed"
    REASONED = "agent.reasoned"
    PROPOSED_ACTION = "agent.proposed_action"
    REQUESTED_AUTHORITY = "agent.requested_authority"
    EXECUTED_ACTION = "agent.executed_action"
    EFFECT_ATTESTED = "agent.attested_effect"
    COMPLETED_WORKFLOW = "agent.completed_workflow"
    EXCEPTION = "agent.encountered_exception"
    FEEDBACK_RECEIVED = "agent.received_human_feedback"


class AuthorityClass(SerializableEnum):
    OBSERVE = "observe"
    SEARCH = "search"
    SUMMARIZE = "summarize"
    CLASSIFY = "classify"
    SCORE = "score"
    RECOMMEND = "recommend"
    DRAFT = "draft"
    MODIFY_INTERNAL_RECORD = "modify_internal_record"
    MODIFY_EXTERNAL_RECORD = "modify_external_record"
    COMMUNICATE_INTERNALLY = "communicate_internally"
    COMMUNICATE_EXTERNALLY = "communicate_externally"
    SCHEDULE = "schedule"
    COMMIT_COMMERCIAL_POSITION = "commit_commercial_position"
    OFFER_PRICING_OR_DISCOUNT = "offer_pricing_or_discount"
    CHANGE_LEGAL_POSITION = "change_legal_position"
    SPEND_MONEY = "spend_money"
    TRANSFER_VALUE = "transfer_value"
    GRANT_ACCESS = "grant_access"
    REVOKE_ACCESS = "revoke_access"
    DELETE_DATA = "delete_data"
    MODIFY_PRODUCTION_SYSTEM = "modify_production_system"
    BIND_ORGANIZATION = "bind_organization"
    ESCALATE_TO_HUMAN = "escalate_to_human"


class ConsequenceClass(SerializableEnum):
    INFORMATIONAL = "informational"
    INTERNAL_ONLY = "internal_only"
    INTERNAL_RECORD_CHANGE = "internal_record_change"
    EXTERNAL_FACING = "external_facing"
    CUSTOMER_IMPACTING = "customer_impacting"
    FINANCIAL = "financial"
    LEGAL = "legal"
    SECURITY_SENSITIVE = "security_sensitive"
    PRODUCTION_IMPACTING = "production_impacting"
    IRREVERSIBLE = "irreversible"
    REPUTATIONAL = "reputational"
    REGULATED = "regulated"


class RiskLevel(SerializableEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AutonomyLevel(int, Enum):
    OBSERVE_ONLY = 0
    SUGGEST = 1
    DRAFT = 2
    EXECUTE_WITH_APPROVAL = 3
    EXECUTE_WITH_SAMPLING = 4
    CONDITIONAL_AUTONOMY = 5
    EXCEPTION_BASED_SUPERVISION = 6
    DELEGATED_AUTHORITY = 7

    @property
    def label(self) -> str:
        return {
            0: "Observe Only",
            1: "Suggest",
            2: "Draft",
            3: "Execute With Approval",
            4: "Execute With Sampling",
            5: "Conditional Autonomy",
            6: "Exception-Based Supervision",
            7: "Delegated Authority",
        }[int(self.value)]


class ApprovalOutcome(SerializableEnum):
    APPROVED = "approved"
    REJECTED = "rejected"
    MODIFIED_AND_APPROVED = "modified_and_approved"
    MORE_EVIDENCE_REQUESTED = "more_evidence_requested"
    ESCALATED = "escalated"
    CONVERTED_TO_DELEGATION_RULE = "converted_to_delegation_rule"


class AutonomyStatus(SerializableEnum):
    ALLOWED = "allowed"
    APPROVAL_REQUIRED = "approval_required"
    SAMPLE_REVIEW = "sample_review"
    ESCALATE = "escalate"
    BLOCKED = "blocked"


# --- Identity & evidence ---------------------------------------------------


@dataclass
class EvidenceItem:
    source: str
    claim: str
    url: Optional[str] = None
    confidence: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AgentIdentity:
    agent_id: str
    name: str
    owner_id: str
    purpose: str
    # Ed25519 public key (hex). Required in strict mode; this is the root of
    # agent accountability — events are only trusted if signed by this key.
    public_key_hex: Optional[str] = None
    approved_workflows: List[str] = field(default_factory=list)
    current_autonomy: Dict[str, int] = field(default_factory=dict)
    known_limitations: List[str] = field(default_factory=list)
    incident_count: int = 0
    active: bool = True
    created_at: str = field(default_factory=utc_now)

    def autonomy_for(self, workflow_id: str, authority_class: AuthorityClass) -> AutonomyLevel:
        # v2 fix: default is OBSERVE_ONLY, not EXECUTE_WITH_APPROVAL. An agent
        # starts at the bottom of the ladder and climbs by earning trust.
        key = f"{workflow_id}:{authority_class.value}"
        return AutonomyLevel(self.current_autonomy.get(key, AutonomyLevel.OBSERVE_ONLY.value))

    def set_autonomy(
        self, workflow_id: str, authority_class: AuthorityClass, level: AutonomyLevel
    ) -> None:
        self.current_autonomy[f"{workflow_id}:{authority_class.value}"] = int(level.value)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# --- Workflow events (now signed + nonced) --------------------------------


@dataclass
class WorkflowEvent:
    agent_id: str
    human_owner_id: str
    workflow_id: str
    workflow_stage: str
    event_type: WorkflowEventType
    intent: str
    authority_requested: AuthorityClass
    proposed_next_state: str
    expected_effect: str
    evidence: List[EvidenceItem] = field(default_factory=list)
    confidence: float = 0.0
    requires_execution: bool = True
    # Replay protection: a per-agent monotonic-ish nonce. The control plane
    # rejects a (agent_id, nonce) pair it has already seen.
    nonce: str = field(default_factory=lambda: uuid4().hex)
    # Detached Ed25519 signature over signing_payload(). Optional so unsigned
    # events can exist in dev mode, but strict mode rejects them.
    signature: Optional[str] = None
    event_id: str = field(default_factory=lambda: new_id("evt"))
    timestamp: str = field(default_factory=utc_now)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def signing_payload(self) -> bytes:
        """Canonical bytes that the agent signs. Deliberately excludes
        server-assigned fields (event_id, timestamp) and the signature itself,
        so the agent can sign before the server sees the event."""
        return canonical_bytes(
            {
                "agent_id": self.agent_id,
                "human_owner_id": self.human_owner_id,
                "workflow_id": self.workflow_id,
                "workflow_stage": self.workflow_stage,
                "event_type": self.event_type.value,
                "intent": self.intent,
                "authority_requested": self.authority_requested.value,
                "proposed_next_state": self.proposed_next_state,
                "expected_effect": self.expected_effect,
                "evidence": [item.to_dict() for item in self.evidence],
                "confidence": self.confidence,
                "requires_execution": self.requires_execution,
                "nonce": self.nonce,
                "metadata": self.metadata,
            }
        )

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["event_type"] = self.event_type.value
        data["authority_requested"] = self.authority_requested.value
        return data


# --- Policy / decision objects --------------------------------------------


@dataclass
class PolicyDecision:
    status: AutonomyStatus
    risk_level: RiskLevel
    consequence_classes: List[ConsequenceClass]
    reason: str
    policy_name: Optional[str] = None
    required_approver_role: Optional[str] = None
    sample_rate: float = 0.0
    # The ceiling that applied to this decision (max autonomy this authority
    # class can ever reach), surfaced for transparency.
    autonomy_ceiling: Optional[int] = None
    # Which requires_approval_if predicates fired, if any.
    triggered_guards: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status.value,
            "risk_level": self.risk_level.value,
            "consequence_classes": [c.value for c in self.consequence_classes],
            "reason": self.reason,
            "policy_name": self.policy_name,
            "required_approver_role": self.required_approver_role,
            "sample_rate": self.sample_rate,
            "autonomy_ceiling": self.autonomy_ceiling,
            "triggered_guards": self.triggered_guards,
        }


@dataclass
class ApprovalDecision:
    event_id: str
    approver_id: str
    outcome: ApprovalOutcome
    # Role of the human approver. Used to enforce separation of duties for
    # consequential authority classes.
    approver_role: Optional[str] = None
    rationale: str = ""
    modifications: Dict[str, Any] = field(default_factory=dict)
    conditions: List[str] = field(default_factory=list)
    created_delegation_rule_id: Optional[str] = None
    decision_id: str = field(default_factory=lambda: new_id("dec"))
    timestamp: str = field(default_factory=utc_now)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["outcome"] = self.outcome.value
        return data


@dataclass
class DelegationRule:
    rule_name: str
    workflow_id: str
    agent_id: str
    authority_class: AuthorityClass
    autonomy_level: AutonomyLevel
    conditions: Dict[str, Any] = field(default_factory=dict)
    # v2 fix: these predicates are now EVALUATED at decision time (see
    # core/conditions.py). If any fires, the rule does not grant autonomy and
    # the action falls back to approval.
    requires_approval_if: List[str] = field(default_factory=list)
    sample_rate: float = 0.0
    active: bool = True
    rule_id: str = field(default_factory=lambda: new_id("rule"))
    created_by: Optional[str] = None
    created_at: str = field(default_factory=utc_now)
    revoked_at: Optional[str] = None
    revoked_reason: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def matches(self, event: WorkflowEvent) -> bool:
        if not self.active:
            return False
        if self.workflow_id != event.workflow_id:
            return False
        if self.agent_id != event.agent_id:
            return False
        if self.authority_class != event.authority_requested:
            return False
        for key, expected in self.conditions.items():
            actual = event.metadata.get(key)
            if isinstance(expected, dict):
                minimum = expected.get("min")
                maximum = expected.get("max")
                if minimum is not None and (actual is None or actual < minimum):
                    return False
                if maximum is not None and (actual is None or actual > maximum):
                    return False
            elif isinstance(expected, list):
                if actual not in expected:
                    return False
            else:
                if actual != expected:
                    return False
        return True

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["authority_class"] = self.authority_class.value
        data["autonomy_level"] = int(self.autonomy_level.value)
        return data


# --- Trust statistics (statistically honest) ------------------------------


def wilson_lower_bound(successes: int, n: int, z: float = 1.96) -> float:
    """Wilson score lower bound on a binomial proportion.

    We use the *lower* bound, not the point estimate, as the trust signal.
    With small n the point estimate is wildly optimistic; the lower bound
    builds in the penalty for thin evidence automatically. z=1.96 ~ 95%.
    """
    if n == 0:
        return 0.0
    phat = successes / n
    denom = 1 + z * z / n
    centre = phat + z * z / (2 * n)
    margin = z * math.sqrt((phat * (1 - phat) + z * z / (4 * n)) / n)
    return max(0.0, (centre - margin) / denom)


@dataclass
class TrustStats:
    agent_id: str
    workflow_id: str
    authority_class: AuthorityClass
    # v2 fix: clean approvals are separated from modified-and-approved. A
    # modification means the human had to fix the agent's work — it is NOT a
    # clean success and must not inflate the trust signal.
    clean_approvals: int = 0
    modified_approvals: int = 0
    rejections: int = 0
    escalations: int = 0
    evidence_requests: int = 0
    incidents: int = 0
    samples_reviewed: int = 0
    # Set of event_ids that have already produced a terminal decision, so a
    # replayed decision against the same event cannot double-count.
    decided_event_ids: List[str] = field(default_factory=list)
    last_updated: str = field(default_factory=utc_now)

    @property
    def total_decisions(self) -> int:
        return (
            self.clean_approvals
            + self.modified_approvals
            + self.rejections
            + self.escalations
            + self.evidence_requests
        )

    @property
    def clean_approval_rate(self) -> float:
        if self.total_decisions == 0:
            return 0.0
        return self.clean_approvals / self.total_decisions

    @property
    def clean_approval_lower_bound(self) -> float:
        """Wilson lower bound on the clean-approval rate. This is THE signal the
        recommendation engine uses to relax autonomy."""
        return wilson_lower_bound(self.clean_approvals, self.total_decisions)

    @property
    def edit_rate(self) -> float:
        if self.total_decisions == 0:
            return 0.0
        return self.modified_approvals / self.total_decisions

    @property
    def rejection_rate(self) -> float:
        if self.total_decisions == 0:
            return 0.0
        return self.rejections / self.total_decisions

    @property
    def incident_rate(self) -> float:
        if self.total_decisions == 0:
            return 0.0
        return self.incidents / max(1, self.total_decisions)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "workflow_id": self.workflow_id,
            "authority_class": self.authority_class.value,
            "clean_approvals": self.clean_approvals,
            "modified_approvals": self.modified_approvals,
            "rejections": self.rejections,
            "escalations": self.escalations,
            "evidence_requests": self.evidence_requests,
            "incidents": self.incidents,
            "samples_reviewed": self.samples_reviewed,
            "total_decisions": self.total_decisions,
            "clean_approval_rate": self.clean_approval_rate,
            "clean_approval_lower_bound": self.clean_approval_lower_bound,
            "edit_rate": self.edit_rate,
            "rejection_rate": self.rejection_rate,
            "incident_rate": self.incident_rate,
            "last_updated": self.last_updated,
        }


@dataclass
class AutonomyRecommendation:
    agent_id: str
    workflow_id: str
    authority_class: AuthorityClass
    current_level: AutonomyLevel
    recommended_level: AutonomyLevel
    confidence: float
    reason: str
    autonomy_ceiling: AutonomyLevel
    proposed_rule: Optional[DelegationRule] = None
    requires_second_approver: bool = False
    recommendation_id: str = field(default_factory=lambda: new_id("rec"))
    created_at: str = field(default_factory=utc_now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "recommendation_id": self.recommendation_id,
            "agent_id": self.agent_id,
            "workflow_id": self.workflow_id,
            "authority_class": self.authority_class.value,
            "current_level": int(self.current_level.value),
            "current_level_label": self.current_level.label,
            "recommended_level": int(self.recommended_level.value),
            "recommended_level_label": self.recommended_level.label,
            "autonomy_ceiling": int(self.autonomy_ceiling.value),
            "autonomy_ceiling_label": self.autonomy_ceiling.label,
            "confidence": self.confidence,
            "reason": self.reason,
            "requires_second_approver": self.requires_second_approver,
            "proposed_rule": self.proposed_rule.to_dict() if self.proposed_rule else None,
            "created_at": self.created_at,
        }


# --- Capability tokens (the enforcement primitive) ------------------------


@dataclass
class CapabilityToken:
    """A short-lived, scoped, signed grant of authority.

    This is the bridge between a *decision* and an *action*. The control plane
    mints one only when a decision resolves to ALLOWED (or after an approval).
    The agent must present it to the Policy Enforcement Point, which checks the
    *actual* action against this scope before letting it execute. Without a
    valid token the PEP blocks — that is what makes the layer enforcing rather
    than advisory.
    """
    token_id: str
    agent_id: str
    workflow_id: str
    authority_class: AuthorityClass
    max_consequence_rank: int
    conditions: Dict[str, Any]
    issued_at: str
    expires_at: str
    nonce: str
    single_use: bool
    issuer: str
    event_id: Optional[str] = None
    signature: Optional[str] = None

    def signing_payload(self) -> bytes:
        return canonical_bytes(
            {
                "token_id": self.token_id,
                "agent_id": self.agent_id,
                "workflow_id": self.workflow_id,
                "authority_class": self.authority_class.value,
                "max_consequence_rank": self.max_consequence_rank,
                "conditions": self.conditions,
                "issued_at": self.issued_at,
                "expires_at": self.expires_at,
                "nonce": self.nonce,
                "single_use": self.single_use,
                "issuer": self.issuer,
                "event_id": self.event_id,
            }
        )

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["authority_class"] = self.authority_class.value
        return data


@dataclass
class AuditRecord:
    event_type: str
    payload: Dict[str, Any]
    actor_id: Optional[str] = None
    record_id: str = field(default_factory=lambda: new_id("aud"))
    timestamp: str = field(default_factory=utc_now)
    sequence: int = 0
    previous_hash: Optional[str] = None
    record_hash: Optional[str] = None
    signature: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
