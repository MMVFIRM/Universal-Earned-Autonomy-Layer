from earned_autonomy.core.conditions import evaluate_guards
from earned_autonomy.crypto import generate_keypair
from helpers import signed_event


def test_unknown_guard_fails_closed():
    ev = signed_event(generate_keypair())
    fired = evaluate_guards(["definitely_not_a_real_guard"], ev)
    assert any("unknown_guard_fail_closed" in f for f in fired)


def test_missing_evidence_guard():
    ev = signed_event(generate_keypair(), with_evidence=False)
    assert "missing_source_evidence" in evaluate_guards(["missing_source_evidence"], ev)


def test_irreversible_guard_from_metadata():
    ev = signed_event(generate_keypair(), metadata={"irreversible": True})
    assert "irreversible" in evaluate_guards(["irreversible"], ev)
