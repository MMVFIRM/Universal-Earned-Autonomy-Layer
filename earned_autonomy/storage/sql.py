"""SQLAlchemy-backed store for production persistence (Postgres or SQLite).

This adapter implements the same `Store` interface as InMemoryStore. It is an
optional dependency path: `pip install -e ".[sql]"`. Domain objects are stored
as JSON columns for v2 (schema-light, migration-friendly); a future version can
normalize hot columns for indexing. Agents/events/rules are upserted; nonces are
a uniqueness-constrained table that enforces replay protection at the DB level.

The unit-test suite runs against InMemoryStore so it needs no live database.
Integration tests for this adapter run against SQLite/Postgres in CI.
"""
from __future__ import annotations

from typing import Optional

try:
    from sqlalchemy import (
        JSON,
        Column,
        String,
        UniqueConstraint,
        create_engine,
        select,
    )
    from sqlalchemy.exc import IntegrityError
    from sqlalchemy.orm import DeclarativeBase, Session
except ImportError as exc:  # pragma: no cover - optional dependency
    raise RuntimeError("SQL extras not installed. Install with: pip install -e '.[sql]'") from exc

from ..core.models import AgentIdentity, AuthorityClass, AutonomyLevel, DelegationRule, WorkflowEvent
from ..core.models import EvidenceItem, WorkflowEventType


class Base(DeclarativeBase):
    pass


class AgentRow(Base):
    __tablename__ = "agents"
    agent_id = Column(String, primary_key=True)
    data = Column(JSON, nullable=False)


class EventRow(Base):
    __tablename__ = "events"
    event_id = Column(String, primary_key=True)
    data = Column(JSON, nullable=False)


class RuleRow(Base):
    __tablename__ = "delegation_rules"
    rule_id = Column(String, primary_key=True)
    agent_id = Column(String, index=True, nullable=False)
    workflow_id = Column(String, index=True, nullable=False)
    authority_class = Column(String, index=True, nullable=False)
    data = Column(JSON, nullable=False)


class NonceRow(Base):
    __tablename__ = "agent_nonces"
    __table_args__ = (UniqueConstraint("agent_id", "nonce", name="uq_agent_nonce"),)
    id = Column(String, primary_key=True)
    agent_id = Column(String, index=True, nullable=False)
    nonce = Column(String, nullable=False)


def _agent_from_data(data: dict) -> AgentIdentity:
    return AgentIdentity(**data)


def _event_from_data(data: dict) -> WorkflowEvent:
    d = dict(data)
    d["event_type"] = WorkflowEventType(d["event_type"])
    d["authority_requested"] = AuthorityClass(d["authority_requested"])
    d["evidence"] = [EvidenceItem(**e) for e in d.get("evidence", [])]
    return WorkflowEvent(**d)


def _rule_from_data(data: dict) -> DelegationRule:
    d = dict(data)
    d["authority_class"] = AuthorityClass(d["authority_class"])
    d["autonomy_level"] = AutonomyLevel(int(d["autonomy_level"]))
    return DelegationRule(**d)


class SqlStore:
    def __init__(self, url: str):
        self.engine = create_engine(url, future=True)
        Base.metadata.create_all(self.engine)

    def add_agent(self, agent: AgentIdentity) -> None:
        with Session(self.engine) as s:
            s.merge(AgentRow(agent_id=agent.agent_id, data=agent.to_dict()))
            s.commit()

    def get_agent(self, agent_id: str) -> Optional[AgentIdentity]:
        with Session(self.engine) as s:
            row = s.get(AgentRow, agent_id)
            return _agent_from_data(row.data) if row else None

    def add_event(self, event: WorkflowEvent) -> None:
        with Session(self.engine) as s:
            s.merge(EventRow(event_id=event.event_id, data=event.to_dict()))
            s.commit()

    def get_event(self, event_id: str) -> Optional[WorkflowEvent]:
        with Session(self.engine) as s:
            row = s.get(EventRow, event_id)
            return _event_from_data(row.data) if row else None

    def add_rule(self, rule: DelegationRule) -> None:
        with Session(self.engine) as s:
            s.merge(RuleRow(
                rule_id=rule.rule_id, agent_id=rule.agent_id, workflow_id=rule.workflow_id,
                authority_class=rule.authority_class.value, data=rule.to_dict(),
            ))
            s.commit()

    def get_rule(self, rule_id: str) -> Optional[DelegationRule]:
        with Session(self.engine) as s:
            row = s.get(RuleRow, rule_id)
            return _rule_from_data(row.data) if row else None

    def matching_rule(self, event: WorkflowEvent) -> Optional[DelegationRule]:
        for rule in self.rules_for(event.agent_id, event.workflow_id, event.authority_requested.value):
            if rule.matches(event):
                return rule
        return None

    def rules_for(self, agent_id: str, workflow_id: str, authority_value: str) -> list[DelegationRule]:
        with Session(self.engine) as s:
            rows = s.execute(
                select(RuleRow).where(
                    RuleRow.agent_id == agent_id,
                    RuleRow.workflow_id == workflow_id,
                    RuleRow.authority_class == authority_value,
                )
            ).scalars().all()
            return [_rule_from_data(r.data) for r in rows]

    def all_active_rules_for_agent(self, agent_id: str) -> list[DelegationRule]:
        with Session(self.engine) as s:
            rows = s.execute(select(RuleRow).where(RuleRow.agent_id == agent_id)).scalars().all()
            rules = [_rule_from_data(r.data) for r in rows]
            return [r for r in rules if r.active]

    def seen_nonce(self, agent_id: str, nonce: str) -> bool:
        with Session(self.engine) as s:
            row = s.execute(
                select(NonceRow).where(NonceRow.agent_id == agent_id, NonceRow.nonce == nonce)
            ).scalars().first()
            return row is not None

    def mark_nonce(self, agent_id: str, nonce: str) -> None:
        from uuid import uuid4
        with Session(self.engine) as s:
            s.add(NonceRow(id=uuid4().hex, agent_id=agent_id, nonce=nonce))
            s.commit()

    def claim_nonce(self, agent_id: str, nonce: str) -> bool:
        """Atomically claim a (agent, nonce) pair. Returns True if THIS call
        claimed it (first writer), False if it was already used.

        This replaces the seen_nonce/mark_nonce check-then-act, which had a
        cross-replica TOCTOU window: two replicas could both observe the nonce
        as unused and both proceed. Here the unique constraint decides a single
        winner; the loser's insert raises IntegrityError and is reported as a
        replay rather than crashing the request.
        """
        from uuid import uuid4
        try:
            with Session(self.engine) as s:
                s.add(NonceRow(id=uuid4().hex, agent_id=agent_id, nonce=nonce))
                s.commit()
            return True
        except IntegrityError:
            return False
