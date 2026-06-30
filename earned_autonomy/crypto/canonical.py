"""Canonical serialization.

Every signature and hash in the system is computed over the *canonical* byte
encoding produced here. Signing and verification must agree byte-for-byte, so
this is the single source of truth for how a Python object becomes bytes.

Rules:
- UTF-8.
- Object keys sorted.
- No insignificant whitespace.
- NaN/Infinity rejected (not valid JSON, and a silent source of hash drift).
"""
from __future__ import annotations

import json
from typing import Any


def canonical_bytes(obj: Any) -> bytes:
    """Return the canonical UTF-8 byte encoding of a JSON-serializable object."""
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
