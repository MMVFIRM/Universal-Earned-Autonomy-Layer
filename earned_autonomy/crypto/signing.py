"""Ed25519 signing primitives.

Thin, auditable wrapper over `cryptography`'s Ed25519. We expose only what the
control plane needs: generate a keypair, sign canonical bytes, verify a
signature against a known public key. Keys are carried as hex strings so they
serialize cleanly into JSON payloads, audit records, and the agent registry.

There is no key *storage* here on purpose. Private keys belong in a secrets
manager / HSM in production; this module only operates on key material handed
to it. See docs/SECURITY_MODEL.md.
"""
from __future__ import annotations

from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


class SignatureError(Exception):
    """Raised when a signature fails verification."""


@dataclass(frozen=True)
class KeyPair:
    private_key_hex: str
    public_key_hex: str

    @property
    def _private(self) -> Ed25519PrivateKey:
        return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(self.private_key_hex))

    def sign(self, message: bytes) -> str:
        return self._private.sign(message).hex()


def generate_keypair() -> KeyPair:
    private = Ed25519PrivateKey.generate()
    private_bytes = private.private_bytes_raw()
    public_bytes = private.public_key().public_bytes_raw()
    return KeyPair(private_key_hex=private_bytes.hex(), public_key_hex=public_bytes.hex())


def sign(private_key_hex: str, message: bytes) -> str:
    private = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_key_hex))
    return private.sign(message).hex()


def verify(public_key_hex: str, message: bytes, signature_hex: str) -> bool:
    """Return True iff `signature_hex` is a valid signature of `message`.

    Never raises on a bad signature — returns False — so callers can branch
    without exception handling. Malformed key/hex input returns False too.
    """
    try:
        public = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
        public.verify(bytes.fromhex(signature_hex), message)
        return True
    except (InvalidSignature, ValueError):
        return False
