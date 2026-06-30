from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Callable, Iterable, List, Optional

from ..crypto import canonical_bytes, sign, verify
from .models import AuditRecord


def hash_record(record: AuditRecord) -> str:
    """Canonical SHA-256 of a record with its hash/signature fields nulled.

    Shared by every ledger implementation (file/in-memory and SQL) so a chain
    written by one can be verified by another byte-for-byte."""
    data = record.to_dict()
    data["record_hash"] = None
    data["signature"] = None
    return hashlib.sha256(canonical_bytes(data)).hexdigest()


class AuditLedger:
    """Append-only, hash-chained, *signed* audit ledger.

    v2 hardening over v1:
      * Every record is Ed25519-signed by the ledger key, so a tamperer cannot
        simply recompute the SHA-256 chain after editing a record — they would
        also need the signing key. v1 was tamper-evident only against
        non-adversarial corruption.
      * Records carry a monotonic sequence number, detecting truncation/reorder.
      * Periodic signed checkpoints summarize the chain head; an external
        anchor callback can post checkpoint hashes to immutable external
        storage (e.g. a transparency log or object-lock bucket) so even someone
        who compromises the ledger key cannot rewrite history undetected.

    The external anchor sink is deployment-provided; the hook is here.
    """

    def __init__(
        self,
        signing_key_hex: str,
        verify_key_hex: str,
        path: Optional[str] = None,
        checkpoint_every: int = 100,
        anchor_sink: Optional[Callable[[dict], None]] = None,
    ):
        self._sign_key = signing_key_hex
        self._verify_key = verify_key_hex
        self.path = Path(path) if path else None
        self.checkpoint_every = checkpoint_every
        self.anchor_sink = anchor_sink
        self._records: List[AuditRecord] = []
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            if self.path.exists():
                self._records = self._load_records(self.path)

    def append(self, event_type: str, payload: dict, actor_id: Optional[str] = None) -> AuditRecord:
        previous_hash = self._records[-1].record_hash if self._records else None
        sequence = len(self._records)
        record = AuditRecord(
            event_type=event_type,
            payload=payload,
            actor_id=actor_id,
            sequence=sequence,
            previous_hash=previous_hash,
        )
        record.record_hash = self._hash_record(record)
        record.signature = sign(self._sign_key, record.record_hash.encode("utf-8"))
        self._records.append(record)
        if self.path:
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(record.to_dict(), sort_keys=True) + "\n")
        if self.checkpoint_every and (sequence + 1) % self.checkpoint_every == 0:
            self._emit_checkpoint()
        return record

    def records(self) -> List[AuditRecord]:
        return list(self._records)

    def verify(self) -> bool:
        previous_hash = None
        for i, record in enumerate(self._records):
            if record.sequence != i:
                return False
            if record.previous_hash != previous_hash:
                return False
            expected_hash = self._hash_record(record)
            if record.record_hash != expected_hash:
                return False
            if record.signature is None or not verify(
                self._verify_key, record.record_hash.encode("utf-8"), record.signature
            ):
                return False
            previous_hash = record.record_hash
        return True

    def _emit_checkpoint(self) -> None:
        head = self._records[-1]
        checkpoint = {
            "type": "ledger_checkpoint",
            "sequence": head.sequence,
            "head_hash": head.record_hash,
            "count": len(self._records),
        }
        checkpoint["signature"] = sign(self._sign_key, canonical_bytes(checkpoint))
        if self.anchor_sink:
            self.anchor_sink(checkpoint)

    def _hash_record(self, record: AuditRecord) -> str:
        return hash_record(record)

    @staticmethod
    def _load_records(path: Path) -> List[AuditRecord]:
        records = []
        with path.open("r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    records.append(AuditRecord(**json.loads(line)))
        return records


def export_records(records: Iterable[AuditRecord]) -> List[dict]:
    return [r.to_dict() for r in records]
