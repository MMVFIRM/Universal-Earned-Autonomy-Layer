from earned_autonomy.core.policy import PolicyEngine
from earned_autonomy.core.ontology import (
    autonomy_ceiling_for, consequences_for, is_irreversible, requires_separation_of_duties,
)
from earned_autonomy.core.models import AuthorityClass, AutonomyLevel, RiskLevel
from earned_autonomy.crypto import generate_keypair
from helpers import signed_event


def evaluate(level, authority, metadata=None):
    return PolicyEngine().evaluate(
        event=signed_event(generate_keypair(), authority=authority, metadata=metadata or {}),
        current_autonomy_level=level,
        consequence_classes=consequences_for(authority),
        classifier_risk=RiskLevel.LOW,
    )


def test_ceiling_clamps_high_risk_class():
    # Even at delegated authority, spend_money hits a boundary rule first.
    d = evaluate(AutonomyLevel.DELEGATED_AUTHORITY, AuthorityClass.SPEND_MONEY)
    assert d.status.value in ("escalate", "approval_required", "blocked")


def test_legal_authority_blocked():
    d = evaluate(AutonomyLevel.DELEGATED_AUTHORITY, AuthorityClass.CHANGE_LEGAL_POSITION)
    assert d.status.value == "blocked"


def test_irreversible_flagged():
    assert is_irreversible(AuthorityClass.DELETE_DATA)
    assert is_irreversible(AuthorityClass.TRANSFER_VALUE)
    assert not is_irreversible(AuthorityClass.OBSERVE)


def test_sod_authorities():
    assert requires_separation_of_duties(AuthorityClass.TRANSFER_VALUE)
    assert not requires_separation_of_duties(AuthorityClass.OBSERVE)


def test_ceiling_values():
    assert autonomy_ceiling_for(AuthorityClass.OBSERVE) == AutonomyLevel.DELEGATED_AUTHORITY
    assert autonomy_ceiling_for(AuthorityClass.COMMUNICATE_EXTERNALLY) == AutonomyLevel.CONDITIONAL_AUTONOMY
    assert autonomy_ceiling_for(AuthorityClass.SPEND_MONEY) == AutonomyLevel.EXECUTE_WITH_SAMPLING
    assert autonomy_ceiling_for(AuthorityClass.DELETE_DATA) == AutonomyLevel.EXECUTE_WITH_APPROVAL
