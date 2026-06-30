import pytest
from earned_autonomy.core.trust import DelegationMemory, ReplayError
from earned_autonomy.core.models import (
    ApprovalDecision, ApprovalOutcome, AuthorityClass, wilson_lower_bound,
)


def test_replay_rejected():
    mem = DelegationMemory()
    d = ApprovalDecision(event_id="e1", approver_id="m", outcome=ApprovalOutcome.APPROVED)
    mem.apply_decision("a", "w", AuthorityClass.MODIFY_INTERNAL_RECORD, d)
    with pytest.raises(ReplayError):
        mem.apply_decision("a", "w", AuthorityClass.MODIFY_INTERNAL_RECORD, d)


def test_wilson_lower_bound_penalizes_small_n():
    # Same point estimate (100%), more evidence -> higher lower bound.
    assert wilson_lower_bound(5, 5) < wilson_lower_bound(50, 50)
    assert wilson_lower_bound(0, 0) == 0.0
    assert 0.0 < wilson_lower_bound(20, 20) < 1.0


def test_clean_vs_modified_separation():
    mem = DelegationMemory()
    for i in range(10):
        mem.apply_decision("a", "w", AuthorityClass.MODIFY_INTERNAL_RECORD,
            ApprovalDecision(event_id=f"e{i}", approver_id="m",
                             outcome=ApprovalOutcome.MODIFIED_AND_APPROVED))
    stats = mem.get("a", "w", AuthorityClass.MODIFY_INTERNAL_RECORD)
    assert stats.clean_approvals == 0 and stats.modified_approvals == 10
    assert stats.clean_approval_lower_bound == 0.0
