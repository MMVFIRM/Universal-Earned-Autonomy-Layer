from earned_autonomy.core.ledger import AuditLedger
from earned_autonomy.crypto import generate_keypair


def make_ledger():
    kp = generate_keypair()
    return AuditLedger(kp.private_key_hex, kp.public_key_hex, checkpoint_every=0)


def test_chain_verifies():
    led = make_ledger()
    for i in range(5):
        led.append("evt", {"i": i})
    assert led.verify()


def test_payload_tamper_detected():
    led = make_ledger()
    for i in range(5):
        led.append("evt", {"i": i})
    led.records()[2].payload["i"] = 999
    assert not led.verify()


def test_signature_required():
    led = make_ledger()
    led.append("evt", {"i": 0})
    led.records()[0].signature = None
    assert not led.verify()


def test_anchor_sink_receives_checkpoint():
    kp = generate_keypair()
    seen = []
    led = AuditLedger(kp.private_key_hex, kp.public_key_hex, checkpoint_every=3,
                      anchor_sink=lambda c: seen.append(c))
    for i in range(3):
        led.append("evt", {"i": i})
    assert len(seen) == 1 and seen[0]["count"] == 3
