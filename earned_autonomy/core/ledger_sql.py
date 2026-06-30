"""Shared SQL audit ledger.

The file/in-memory `AuditLedger` is per-process: under horizontal scaling each
replica produces its own independent chain. For a single, globally-ordered,
verifiable audit trail across replicas, the chain must be appended to under a
serialization guarantee so that sequence numbers and previous-hash links stay
consistent.

`SqlAuditLedger` provides that. Appends run inside a transaction that takes a
lock before reading the chain head and inserting the next record:

  * On PostgreSQL: `pg_advisory_xact_lock` serializes appends cluster-wide; the
    lock is released automatically at commit/rollback.
  * On SQLite: writers are serialized by the database write lock (a busy
    timeout is set), which gives the same guarantee for the single-file case.

Verification recomputes the chain exactly as the file ledger does, using the
shared `hash_record` helper, so a chain written here verifies identically.

Anchoring: `verify()` and `head()` expose what an external anchoring job needs;
the periodic signed-checkpoint emission is left to that job in the multi-writer
case (a single writer emitting checkpoints avoids duplicate anchors). The hook
contract is unchanged from the file ledger.
"""
from __future__ import annotations

from typing import List, Optional

from ..crypto import sign, verify
from .ledger import hash_record
from .models import AuditRecord, new_id, utc_now

try:
    from sqlalchemy import (
        JSON,
        Column,
        Integer,
        MetaData,
        String,
        Table,
        select,
        text,
    )
    from sqlalchemy.engine import Engine
    from sqlalchemy import create_engine, event
except Exception:  # pragma: no cover - optional dependency path
    SqlAuditLedger = None  # type: ignore
else:

    _ADVISORY_LOCK_KEY = 0x4541_4C30  # "EAL0"

    def _force_sqlite_immediate(engine) -> None:
        """Make every transaction on a SQLite engine BEGIN IMMEDIATE so the
        append's read-then-write (read head, insert next) is serialized across
        connections. pysqlite otherwise opens deferred transactions and lets two
        writers read the same head and collide on the sequence primary key."""

        @event.listens_for(engine, "connect")
        def _disable_pysqlite_autobegin(dbapi_conn, _rec):  # pragma: no cover - driver glue
            dbapi_conn.isolation_level = None

        @event.listens_for(engine, "begin")
        def _emit_immediate(conn):  # pragma: no cover - driver glue
            conn.exec_driver_sql("BEGIN IMMEDIATE")

    class SqlAuditLedger:
        def __init__(self, signing_key_hex: str, verify_key_hex: str, url_or_engine):
            self._sign_key = signing_key_hex
            self._verify_key = verify_key_hex
            if isinstance(url_or_engine, str):
                connect_args = {"timeout": 30} if url_or_engine.startswith("sqlite") else {}
                self.engine: Engine = create_engine(url_or_engine, future=True, connect_args=connect_args)
            else:
                self.engine = url_or_engine
            self._dialect = self.engine.dialect.name
            if self._dialect == "sqlite":
                _force_sqlite_immediate(self.engine)
            self.metadata = MetaData()
            self.ledger = Table(
                "audit_ledger",
                self.metadata,
                Column("sequence", Integer, primary_key=True, autoincrement=False),
                Column("record_id", String, nullable=False),
                Column("event_type", String, nullable=False),
                Column("actor_id", String, nullable=True),
                Column("timestamp", String, nullable=False),
                Column("payload", JSON, nullable=False),
                Column("previous_hash", String, nullable=True),
                Column("record_hash", String, nullable=False),
                Column("signature", String, nullable=False),
            )
            self.metadata.create_all(self.engine)

        def append(self, event_type: str, payload: dict, actor_id: Optional[str] = None) -> AuditRecord:
            with self.engine.begin() as conn:
                if self._dialect == "postgresql":
                    conn.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": _ADVISORY_LOCK_KEY})
                # Read the current head under the lock.
                row = conn.execute(
                    select(self.ledger.c.sequence, self.ledger.c.record_hash)
                    .order_by(self.ledger.c.sequence.desc())
                    .limit(1)
                ).first()
                if row is None:
                    sequence = 0
                    previous_hash = None
                else:
                    sequence = int(row[0]) + 1
                    previous_hash = row[1]

                record = AuditRecord(
                    event_type=event_type,
                    payload=payload,
                    actor_id=actor_id,
                    record_id=new_id("aud"),
                    timestamp=utc_now(),
                    sequence=sequence,
                    previous_hash=previous_hash,
                )
                record.record_hash = hash_record(record)
                record.signature = sign(self._sign_key, record.record_hash.encode("utf-8"))

                conn.execute(
                    self.ledger.insert().values(
                        sequence=record.sequence,
                        record_id=record.record_id,
                        event_type=record.event_type,
                        actor_id=record.actor_id,
                        timestamp=record.timestamp,
                        payload=record.payload,
                        previous_hash=record.previous_hash,
                        record_hash=record.record_hash,
                        signature=record.signature,
                    )
                )
            return record

        def records(self) -> List[AuditRecord]:
            with self.engine.connect() as conn:
                rows = conn.execute(
                    select(self.ledger).order_by(self.ledger.c.sequence.asc())
                ).mappings().all()
            return [
                AuditRecord(
                    event_type=r["event_type"],
                    payload=r["payload"],
                    actor_id=r["actor_id"],
                    record_id=r["record_id"],
                    timestamp=r["timestamp"],
                    sequence=r["sequence"],
                    previous_hash=r["previous_hash"],
                    record_hash=r["record_hash"],
                    signature=r["signature"],
                )
                for r in rows
            ]

        def verify(self) -> bool:
            previous_hash = None
            for i, record in enumerate(self.records()):
                if record.sequence != i:
                    return False
                if record.previous_hash != previous_hash:
                    return False
                if record.record_hash != hash_record(record):
                    return False
                if record.signature is None or not verify(
                    self._verify_key, record.record_hash.encode("utf-8"), record.signature
                ):
                    return False
                previous_hash = record.record_hash
            return True

        def head(self) -> Optional[dict]:
            with self.engine.connect() as conn:
                row = conn.execute(
                    select(self.ledger.c.sequence, self.ledger.c.record_hash)
                    .order_by(self.ledger.c.sequence.desc())
                    .limit(1)
                ).first()
            if row is None:
                return None
            return {"sequence": int(row[0]), "head_hash": row[1]}
