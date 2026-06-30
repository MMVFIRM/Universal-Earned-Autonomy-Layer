import time
from earned_autonomy.core.capability import CapabilityService
from earned_autonomy.core.models import AuthorityClass
from earned_autonomy.crypto import generate_keypair


def svc():
    kp = generate_keypair()
    return CapabilityService(kp.private_key_hex, kp.public_key_hex)


def test_valid_token_verifies():
    s = svc()
    t = s.mint("a", "w", AuthorityClass.MODIFY_INTERNAL_RECORD, {}, 300, True)
    r = s.verify_for_action(t, "a", "w", AuthorityClass.MODIFY_INTERNAL_RECORD)
    assert r.ok


def test_single_use_consumed():
    s = svc()
    t = s.mint("a", "w", AuthorityClass.MODIFY_INTERNAL_RECORD, {}, 300, True)
    assert s.verify_for_action(t, "a", "w", AuthorityClass.MODIFY_INTERNAL_RECORD).ok
    assert not s.verify_for_action(t, "a", "w", AuthorityClass.MODIFY_INTERNAL_RECORD).ok


def test_expired_token_rejected():
    s = svc()
    t = s.mint("a", "w", AuthorityClass.MODIFY_INTERNAL_RECORD, {}, 0, True)
    time.sleep(0.01)
    assert not s.verify_for_action(t, "a", "w", AuthorityClass.MODIFY_INTERNAL_RECORD).ok


def test_revoked_token_rejected():
    s = svc()
    t = s.mint("a", "w", AuthorityClass.MODIFY_INTERNAL_RECORD, {}, 300, False)
    s.revoke(t.token_id)
    assert not s.verify_for_action(t, "a", "w", AuthorityClass.MODIFY_INTERNAL_RECORD).ok


def test_tampered_token_rejected():
    s = svc()
    t = s.mint("a", "w", AuthorityClass.MODIFY_INTERNAL_RECORD, {}, 300, False)
    t.max_consequence_rank = 99  # tamper after signing
    assert not s.verify_for_action(t, "a", "w", AuthorityClass.MODIFY_INTERNAL_RECORD).ok


def test_condition_enforced_against_action_context():
    s = svc()
    t = s.mint("a", "w", AuthorityClass.MODIFY_INTERNAL_RECORD, {"region": "us"}, 300, False)
    assert not s.verify_for_action(t, "a", "w", AuthorityClass.MODIFY_INTERNAL_RECORD, {"region": "eu"}).ok
    assert s.verify_for_action(t, "a", "w", AuthorityClass.MODIFY_INTERNAL_RECORD, {"region": "us"}).ok
