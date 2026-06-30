"""Shared state backend for capability tokens.

A capability token asserts a once-only guarantee (`single_use=True`). Enforcing
that guarantee requires that *consumption* be atomic and *shared* across every
process that can verify a token. In v2.1 consumption, revocation, and the issued
index lived in `CapabilityService` process memory, so under horizontal scaling a
single-use token consumed on one replica was re-accepted on another, and a
revocation processed on one replica was invisible to the others.

This module factors that state out behind `CapabilityStateStore`. The default
(`InMemoryCapabilityStore`) preserves the single-process behavior for tests and
embedded use. `SqlCapabilityStore` makes the three operations that MUST be
globally consistent — consume, revoke, revoke-by-scope — atomic at the database,
so the once-only guarantee holds across replicas.

The crux is `try_consume`: a single conditional UPDATE
    UPDATE capability_tokens SET consumed=1
    WHERE token_id=:id AND consumed=0 AND revoked=0
whose row lock serializes concurrent attempts. Exactly one caller observes
rowcount==1; everyone else observes 0. There is no read-then-write window, so
the cross-replica TOCTOU race is closed. The same statement also rejects a token
revoked concurrently (the `revoked=0` predicate), so revoke-versus-consume is
decided by whichever transaction commits first.
"""
from __future__ import annotations

import threading
from datetime import datetime, timezone
from typing import Dict, Optional, Protocol, Tuple


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class CapabilityStateStore(Protocol):
    def record_issued(
        self, token_id: str, agent_id: str, workflow_id: str, authority_value: str, expires_at_iso: str
    ) -> None: ...
    def try_consume(self, token_id: str) -> bool: ...
    def is_consumed(self, token_id: str) -> bool: ...
    def revoke(self, token_id: str) -> None: ...
    def is_revoked(self, token_id: str) -> bool: ...
    def revoke_scope(self, agent_id: str, workflow_id: str, authority_value: str) -> int: ...
    def purge_expired(self, now_iso: Optional[str] = None) -> int: ...


class InMemoryCapabilityStore:
    """Single-process backend. Thread-safe via a lock so `try_consume` is atomic
    within the process. Not shared across processes — use SqlCapabilityStore for
    multi-replica deployments."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # token_id -> (agent, workflow, authority, expires_at_iso)
        self._issued: Dict[str, Tuple[str, str, str, str]] = {}
        self._consumed: set[str] = set()
        self._revoked: set[str] = set()

    def record_issued(self, token_id, agent_id, workflow_id, authority_value, expires_at_iso) -> None:
        with self._lock:
            self._issued[token_id] = (agent_id, workflow_id, authority_value, expires_at_iso)

    def try_consume(self, token_id: str) -> bool:
        with self._lock:
            if token_id in self._consumed or token_id in self._revoked:
                return False
            self._consumed.add(token_id)
            return True

    def is_consumed(self, token_id: str) -> bool:
        with self._lock:
            return token_id in self._consumed

    def revoke(self, token_id: str) -> None:
        with self._lock:
            self._revoked.add(token_id)

    def is_revoked(self, token_id: str) -> bool:
        with self._lock:
            return token_id in self._revoked

    def revoke_scope(self, agent_id: str, workflow_id: str, authority_value: str) -> int:
        scope = (agent_id, workflow_id, authority_value)
        revoked = 0
        with self._lock:
            for token_id, (a, w, c, _exp) in self._issued.items():
                if (a, w, c) == scope and token_id not in self._revoked and token_id not in self._consumed:
                    self._revoked.add(token_id)
                    revoked += 1
        return revoked

    def purge_expired(self, now_iso: Optional[str] = None) -> int:
        now = now_iso or _now_iso()
        with self._lock:
            expired = [t for t, (_a, _w, _c, exp) in self._issued.items() if exp < now]
            for t in expired:
                self._issued.pop(t, None)
                self._consumed.discard(t)
                self._revoked.discard(t)
        return len(expired)


try:
    from sqlalchemy import (
        Boolean,
        Column,
        MetaData,
        String,
        Table,
        and_,
        create_engine,
        delete,
        insert,
        select,
        update,
    )
    from sqlalchemy.engine import Engine
    from sqlalchemy.exc import IntegrityError
except Exception:  # pragma: no cover - optional dependency path
    SqlCapabilityStore = None  # type: ignore
else:

    class SqlCapabilityStore:
        """Postgres/SQLite-backed capability state. Makes consume/revoke globally
        atomic so single-use holds across replicas.

        Accepts a database URL or an existing Engine (so it can share a pool with
        the main SqlStore). The table is created on construction.
        """

        def __init__(self, url_or_engine):
            if isinstance(url_or_engine, str):
                self.engine: Engine = create_engine(url_or_engine, future=True)
            else:
                self.engine = url_or_engine
            self.metadata = MetaData()
            self.tokens = Table(
                "capability_tokens",
                self.metadata,
                Column("token_id", String, primary_key=True),
                Column("agent_id", String, index=True, nullable=False),
                Column("workflow_id", String, index=True, nullable=False),
                Column("authority_class", String, index=True, nullable=False),
                Column("expires_at", String, nullable=False),
                Column("consumed", Boolean, nullable=False, default=False),
                Column("revoked", Boolean, nullable=False, default=False),
            )
            self.metadata.create_all(self.engine)

        def record_issued(self, token_id, agent_id, workflow_id, authority_value, expires_at_iso) -> None:
            stmt = insert(self.tokens).values(
                token_id=token_id, agent_id=agent_id, workflow_id=workflow_id,
                authority_class=authority_value, expires_at=expires_at_iso,
                consumed=False, revoked=False,
            )
            try:
                with self.engine.begin() as conn:
                    conn.execute(stmt)
            except IntegrityError:
                # Token id already recorded (uuid collision is effectively
                # impossible; this just keeps record_issued idempotent).
                pass

        def try_consume(self, token_id: str) -> bool:
            """Atomically mark a token consumed iff it is neither already consumed
            nor revoked. Exactly one concurrent caller wins (rowcount == 1)."""
            stmt = (
                update(self.tokens)
                .where(
                    and_(
                        self.tokens.c.token_id == token_id,
                        self.tokens.c.consumed.is_(False),
                        self.tokens.c.revoked.is_(False),
                    )
                )
                .values(consumed=True)
            )
            with self.engine.begin() as conn:
                result = conn.execute(stmt)
                return result.rowcount == 1

        def is_consumed(self, token_id: str) -> bool:
            with self.engine.connect() as conn:
                row = conn.execute(
                    select(self.tokens.c.consumed).where(self.tokens.c.token_id == token_id)
                ).first()
                return bool(row[0]) if row else False

        def revoke(self, token_id: str) -> None:
            stmt = update(self.tokens).where(self.tokens.c.token_id == token_id).values(revoked=True)
            with self.engine.begin() as conn:
                conn.execute(stmt)

        def is_revoked(self, token_id: str) -> bool:
            with self.engine.connect() as conn:
                row = conn.execute(
                    select(self.tokens.c.revoked).where(self.tokens.c.token_id == token_id)
                ).first()
                return bool(row[0]) if row else False

        def revoke_scope(self, agent_id: str, workflow_id: str, authority_value: str) -> int:
            stmt = (
                update(self.tokens)
                .where(
                    and_(
                        self.tokens.c.agent_id == agent_id,
                        self.tokens.c.workflow_id == workflow_id,
                        self.tokens.c.authority_class == authority_value,
                        self.tokens.c.revoked.is_(False),
                        self.tokens.c.consumed.is_(False),
                    )
                )
                .values(revoked=True)
            )
            with self.engine.begin() as conn:
                return conn.execute(stmt).rowcount

        def purge_expired(self, now_iso: Optional[str] = None) -> int:
            now = now_iso or _now_iso()
            stmt = delete(self.tokens).where(self.tokens.c.expires_at < now)
            with self.engine.begin() as conn:
                return conn.execute(stmt).rowcount
