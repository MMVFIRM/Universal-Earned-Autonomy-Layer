from __future__ import annotations

from typing import Any, Dict, List, Optional

try:
    from pydantic import BaseModel, Field
except ImportError as exc:  # pragma: no cover - optional dep
    raise RuntimeError("API extras not installed. Install with: pip install -e '.[api]'") from exc


class EvidenceIn(BaseModel):
    source: str
    claim: str
    url: Optional[str] = None
    confidence: Optional[float] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class RegisterAgentIn(BaseModel):
    agent_id: str
    name: str
    owner_id: str
    purpose: str
    public_key_hex: str
    approved_workflows: List[str] = Field(default_factory=list)


class ProposeEventIn(BaseModel):
    agent_id: str
    human_owner_id: str
    workflow_id: str
    workflow_stage: str
    intent: str
    authority_requested: str
    proposed_next_state: str
    expected_effect: str
    evidence: List[EvidenceIn] = Field(default_factory=list)
    confidence: float = 0.0
    requires_execution: bool = True
    nonce: str
    signature: str
    event_type: str = "agent.proposed_action"
    metadata: Dict[str, Any] = Field(default_factory=dict)


class DecisionIn(BaseModel):
    event_id: str
    approver_id: str
    outcome: str
    approver_role: Optional[str] = None
    rationale: str = ""
    modifications: Dict[str, Any] = Field(default_factory=dict)


class DelegationRuleIn(BaseModel):
    rule_name: str
    workflow_id: str
    agent_id: str
    authority_class: str
    autonomy_level: int
    conditions: Dict[str, Any] = Field(default_factory=dict)
    requires_approval_if: List[str] = Field(default_factory=list)
    sample_rate: float = 0.0
    approver_id: str
    approver_role: Optional[str] = None


class IncidentIn(BaseModel):
    agent_id: str
    workflow_id: str
    authority_class: str
    reason: str
    actor_id: str
