from __future__ import annotations

from typing import Dict, List, Tuple

from .models import (
    ApprovalDecision,
    ApprovalOutcome,
    AuthorityClass,
    TrustStats,
    utc_now,
)

StatsKey = Tuple[str, str, str]


class ReplayError(Exception):
    """Raised when a terminal decision is submitted twice for one event."""


class DelegationMemory:
    """Stores approval patterns by agent, workflow, and authority class.

    v2 fix: a terminal decision is recorded at most once per event_id. In v1 the
    demo submitted 25 approvals against a single event and the trust counter
    happily counted all 25, so `total_decisions` measured button clicks, not
    distinct vetted actions. Here a replayed decision raises ReplayError and does
    not mutate stats.
    """

    def __init__(self) -> None:
        self._stats: Dict[StatsKey, TrustStats] = {}

    @staticmethod
    def key(agent_id: str, workflow_id: str, authority_class: AuthorityClass) -> StatsKey:
        return (agent_id, workflow_id, authority_class.value)

    def get(self, agent_id: str, workflow_id: str, authority_class: AuthorityClass) -> TrustStats:
        key = self.key(agent_id, workflow_id, authority_class)
        if key not in self._stats:
            self._stats[key] = TrustStats(
                agent_id=agent_id, workflow_id=workflow_id, authority_class=authority_class
            )
        return self._stats[key]

    def apply_decision(
        self,
        agent_id: str,
        workflow_id: str,
        authority_class: AuthorityClass,
        decision: ApprovalDecision,
    ) -> TrustStats:
        stats = self.get(agent_id, workflow_id, authority_class)
        if decision.event_id in stats.decided_event_ids:
            raise ReplayError(
                f"event {decision.event_id} already has a terminal decision; refusing to double-count"
            )
        stats.decided_event_ids.append(decision.event_id)

        outcome = decision.outcome
        if outcome == ApprovalOutcome.APPROVED:
            stats.clean_approvals += 1
        elif outcome == ApprovalOutcome.CONVERTED_TO_DELEGATION_RULE:
            stats.clean_approvals += 1
        elif outcome == ApprovalOutcome.MODIFIED_AND_APPROVED:
            # A modification is a partial failure (the human had to fix the
            # agent's work). Tracked separately; it does NOT count as a clean
            # success and so does not lift the trust lower bound.
            stats.modified_approvals += 1
        elif outcome == ApprovalOutcome.REJECTED:
            stats.rejections += 1
        elif outcome == ApprovalOutcome.ESCALATED:
            stats.escalations += 1
        elif outcome == ApprovalOutcome.MORE_EVIDENCE_REQUESTED:
            stats.evidence_requests += 1
        stats.last_updated = utc_now()
        return stats

    def record_incident(self, agent_id: str, workflow_id: str, authority_class: AuthorityClass) -> TrustStats:
        stats = self.get(agent_id, workflow_id, authority_class)
        stats.incidents += 1
        stats.last_updated = utc_now()
        return stats

    def record_sample_review(self, agent_id: str, workflow_id: str, authority_class: AuthorityClass) -> TrustStats:
        stats = self.get(agent_id, workflow_id, authority_class)
        stats.samples_reviewed += 1
        stats.last_updated = utc_now()
        return stats

    def all_stats(self) -> List[TrustStats]:
        return list(self._stats.values())

    def to_dict(self) -> dict:
        return {"stats": [s.to_dict() for s in self.all_stats()]}
