"""v3 distributed-state and operability tests.

Covers the two remaining shared-state correctness gaps closed in v3 (audit ledger
and nonce replay), plus the operator metrics endpoint.
"""
from __future__ import annotations

import threading

import pytest

from earned_autonomy.core.models import AuthorityClass
from earned_autonomy.crypto import generate_keypair
from helpers import make_agent_with_key, make_cp, signed_event

try:
    from earned_autonomy.core.ledger_sql import SqlAuditLedger
    from earned_autonomy.storage.sql import SqlStore
    _HAVE_SQL = SqlAuditLedger is not None and SqlStore is not None
except Exception:  # pragma: no cover
    _HAVE_SQL = False

sql_only = pytest.mark.skipif(not _HAVE_SQL, reason="SQL extras not installed")


# ---- shared SQL audit ledger ----

@sql_only
def test_two_replicas_share_one_verifiable_chain(tmp_path):
    kp = generate_keypair()
    url = f"sqlite:///{tmp_path/'ledger.db'}"
    a = SqlAuditLedger(kp.private_key_hex, kp.public_key_hex, url)
    b = SqlAuditLedger(kp.private_key_hex, kp.public_key_hex, url)
    for i in range(4):
        a.append("evt.a", {"i": i}, actor_id="a")
    for i in range(4):
        b.append("evt.b", {"i": i}, actor_id="b")
    assert len(a.records()) == 8
    assert a.verify() is True
    assert b.verify() is True
    assert a.head()["sequence"] == b.head()["sequence"] == 7


@sql_only
def test_sql_ledger_detects_tamper(tmp_path):
    kp = generate_keypair()
    url = f"sqlite:///{tmp_path/'ledger.db'}"
    led = SqlAuditLedger(kp.private_key_hex, kp.public_key_hex, url)
    for i in range(3):
        led.append("evt", {"i": i})
    # Tamper directly in the database (simulating someone with table write access).
    from sqlalchemy import update
    with led.engine.begin() as conn:
        conn.execute(update(led.ledger).where(led.ledger.c.sequence == 1).values(payload={"i": 999}))
    assert led.verify() is False


@sql_only
def test_concurrent_ledger_appends_stay_chained(tmp_path):
    kp = generate_keypair()
    url = f"sqlite:///{tmp_path/'ledger.db'}"
    SqlAuditLedger(kp.private_key_hex, kp.public_key_hex, url)  # create table

    def writer():
        led = SqlAuditLedger(kp.private_key_hex, kp.public_key_hex, url)
        for i in range(4):
            led.append("evt", {"i": i})

    threads = [threading.Thread(target=writer) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    verifier = SqlAuditLedger(kp.private_key_hex, kp.public_key_hex, url)
    records = verifier.records()
    assert len(records) == 20
    assert [r.sequence for r in records] == list(range(20))  # contiguous, no gaps/dupes
    assert verifier.verify() is True


# ---- atomic nonce replay protection ----

@sql_only
def test_nonce_claim_atomic_across_instances(tmp_path):
    url = f"sqlite:///{tmp_path/'store.db'}"
    a = SqlStore(url)
    b = SqlStore(url)
    assert a.claim_nonce("ag", "n1") is True
    assert b.claim_nonce("ag", "n1") is False  # second replica sees it as used


def test_nonce_claim_atomic_in_memory_under_threads():
    cp = make_cp()
    store = cp.store
    wins = []
    barrier = threading.Barrier(10)

    def attempt():
        barrier.wait()
        if store.claim_nonce("ag", "shared-nonce"):
            wins.append(1)

    threads = [threading.Thread(target=attempt) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sum(wins) == 1  # exactly one claim wins


def test_replayed_event_rejected_via_claim():
    from earned_autonomy.core import AuthenticationError
    cp = make_cp()
    kp = make_agent_with_key(cp)
    ev = signed_event(kp)
    cp.propose_event(ev)
    with pytest.raises(AuthenticationError):
        cp.propose_event(ev)  # same nonce -> replay


# ---- metrics ----

def test_metrics_endpoint_counts_decisions():
    from fastapi.testclient import TestClient

    from earned_autonomy.api.server import create_app
    from earned_autonomy.config import Settings

    cp = make_cp()
    kp = make_agent_with_key(cp)
    # Two proposals -> two decisions recorded in metrics.
    cp.propose_event(signed_event(kp))
    cp.propose_event(signed_event(kp, authority=AuthorityClass.OBSERVE, requires_execution=False))

    app = create_app(control_plane=cp, settings=Settings(strict_mode=False, dev_auth_secret="x" * 32))
    client = TestClient(app)
    res = client.get("/metrics")
    assert res.status_code == 200
    body = res.text
    assert "eal_decisions_total" in body
    assert "eal_approval_burden_rate" in body
