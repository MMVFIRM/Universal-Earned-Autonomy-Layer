from earned_autonomy.crypto import canonical_bytes, generate_keypair, sign, verify


def test_sign_verify_roundtrip():
    kp = generate_keypair()
    msg = canonical_bytes({"b": 2, "a": 1})
    sig = sign(kp.private_key_hex, msg)
    assert verify(kp.public_key_hex, msg, sig)


def test_verify_rejects_tampered_message():
    kp = generate_keypair()
    sig = sign(kp.private_key_hex, b"hello")
    assert not verify(kp.public_key_hex, b"hell0", sig)


def test_verify_rejects_wrong_key():
    kp = generate_keypair()
    other = generate_keypair()
    sig = sign(kp.private_key_hex, b"hello")
    assert not verify(other.public_key_hex, b"hello", sig)


def test_canonical_is_order_independent():
    assert canonical_bytes({"a": 1, "b": 2}) == canonical_bytes({"b": 2, "a": 1})
