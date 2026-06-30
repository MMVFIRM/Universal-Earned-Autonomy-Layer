"""Tests for the shared, atomic capability-state backend (v2.2).

These reproduce the v2.1 multi-instance gap and prove it is closed: two
CapabilityService instances sharing one SQL backend (modeling two API replicas
behind a load balancer) must agree on consumption and revocation.
"""
from __future__ import annotations

import threading

import pytest

from earned_autonomy.core.capability import CapabilityService
from earned_autonomy.core.capability_store import (
    InMemoryCapabilityStore,
    SqlCapabilityStore,
)
from earned_autonomy.core.models import AuthorityClass
from earned_autonomy.crypto import generate_keypair

AUTH = AuthorityClass.MODIFY_INTERNAL_RECORD

pytestmark = pytest.mark.skipif(SqlCapabilityStore is None, reason="SQL extras not installed")


def _two_replicas(tmp_path):
    """Two CapabilityService instances sharing one SQLite file = two replicas
    with separate connection pools but shared capability state."""
    kp = generate_keypair()
    url = f"sqlite:///{tmp_path/'caps.db'}"
    store_a = SqlCapabilityStore(url)
    store_b = SqlCapabilityStore(url)
    a = CapabilityService(kp.private_key_hex, kp.public_key_hex, state_store=store_a)
    b = CapabilityService(kp.private_key_hex, kp.public_key_hex, state_store=store_b)
    return a, b


def test_single_use_not_replayable_across_replicas(tmp_path):
    a, b = _two_replicas(tmp_path)
    token = a.mint("ag", "w", AUTH, {}, 300, single_use=True)
    # Consumed on replica A...
    assert a.verify_for_action(token, "ag", "w", AUTH).ok is True
    # ...must be rejected on replica B (the v2.1 gap; now closed).
    result_b = b.verify_for_action(token, "ag", "w", AUTH)
    assert result_b.ok is False
    assert "consumed" in result_b.reason


def test_revocation_visible_across_replicas(tmp_path):
    a, b = _two_replicas(tmp_path)
    token = a.mint("ag", "w", AUTH, {}, 300, single_use=True)
    # Incident handled on replica A revokes by scope.
    assert a.revoke_scope("ag", "w", AUTH) == 1
    result_b = b.verify_for_action(token, "ag", "w", AUTH)
    assert result_b.ok is False
    assert "revoked" in result_b.reason


def test_revoke_scope_does_not_touch_siblings(tmp_path):
    a, b = _two_replicas(tmp_path)
    t_modify = a.mint("ag", "w", AUTH, {}, 300, single_use=True)
    t_comm = a.mint("ag", "w", AuthorityClass.COMMUNICATE_INTERNALLY, {}, 300, single_use=True)
    assert a.revoke_scope("ag", "w", AUTH) == 1
    assert b.verify_for_action(t_modify, "ag", "w", AUTH).ok is False
    assert b.verify_for_action(t_comm, "ag", "w", AuthorityClass.COMMUNICATE_INTERNALLY).ok is True


def test_try_consume_is_single_winner(tmp_path):
    a, _ = _two_replicas(tmp_path)
    token = a.mint("ag", "w", AUTH, {}, 300, single_use=True)
    assert a.state.try_consume(token.token_id) is True
    assert a.state.try_consume(token.token_id) is False


def test_concurrent_consume_exactly_one_winner(tmp_path):
    """Real thread contention: many replicas race to consume one token; exactly
    one may win. SQLite serializes writers, which is precisely the guarantee we
    need — the conditional UPDATE lets only the first transaction match a row."""
    kp = generate_keypair()
    url = f"sqlite:///{tmp_path/'race.db'}"
    seed_store = SqlCapabilityStore(url)
    svc = CapabilityService(kp.private_key_hex, kp.public_key_hex, state_store=seed_store)
    token = svc.mint("ag", "w", AUTH, {}, 300, single_use=True)

    wins = []
    barrier = threading.Barrier(8)

    def attempt():
        # Each thread is its own "replica" with its own store/connection pool.
        store = SqlCapabilityStore(url)
        replica = CapabilityService(kp.private_key_hex, kp.public_key_hex, state_store=store)
        barrier.wait()
        if replica.verify_for_action(token, "ag", "w", AUTH).ok:
            wins.append(1)

    threads = [threading.Thread(target=attempt) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert sum(wins) == 1  # the once-only guarantee holds under contention


def test_purge_expired_removes_rows(tmp_path):
    a, _ = _two_replicas(tmp_path)
    a.mint("ag", "w", AUTH, {}, ttl_seconds=-1, single_use=True)  # already expired
    a.mint("ag", "w", AUTH, {}, ttl_seconds=300, single_use=True)
    removed = a.purge_expired()
    assert removed == 1


def test_inmemory_store_still_enforces_single_use():
    kp = generate_keypair()
    svc = CapabilityService(kp.private_key_hex, kp.public_key_hex, state_store=InMemoryCapabilityStore())
    token = svc.mint("ag", "w", AUTH, {}, 300, single_use=True)
    assert svc.verify_for_action(token, "ag", "w", AUTH).ok is True
    assert svc.verify_for_action(token, "ag", "w", AUTH).ok is False
