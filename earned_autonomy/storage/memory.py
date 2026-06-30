from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Dict, Optional, Protocol, Tuple

from ..core.models import AgentIdentity, DelegationRule, WorkflowEvent


class Store(Protocol):
    def add_agent(self, agent: AgentIdentity) -> None: ...
    def get_agent(self, agent_id: str) -> Optional[AgentIdentity]: ...
    def add_event(self, event: WorkflowEvent) -> None: ...
    def get_event(self, event_id: str) -> Optional[WorkflowEvent]: ...
    def add_rule(self, rule: DelegationRule) -> None: ...
    def get_rule(self, rule_id: str) -> Optional[DelegationRule]: ...
    def matching_rule(self, event: WorkflowEvent) -> Optional[DelegationRule]: ...
    def rules_for(self, agent_id: str, workflow_id: str, authority_value: str) -> list[DelegationRule]: ...
    def all_active_rules_for_agent(self, agent_id: str) -> list[DelegationRule]: ...
    def seen_nonce(self, agent_id: str, nonce: str) -> bool: ...
    def mark_nonce(self, agent_id: str, nonce: str) -> None: ...
    def claim_nonce(self, agent_id: str, nonce: str) -> bool: ...


class InMemoryStore:
    def __init__(self) -> None:
        self.agents: Dict[str, AgentIdentity] = {}
        self.events: Dict[str, WorkflowEvent] = {}
        self.rules: Dict[str, DelegationRule] = {}
        self._nonces: set[Tuple[str, str]] = set()
        self._nonce_lock = threading.Lock()

    def add_agent(self, agent: AgentIdentity) -> None:
        self.agents[agent.agent_id] = agent

    def get_agent(self, agent_id: str) -> Optional[AgentIdentity]:
        return self.agents.get(agent_id)

    def add_event(self, event: WorkflowEvent) -> None:
        self.events[event.event_id] = event

    def get_event(self, event_id: str) -> Optional[WorkflowEvent]:
        return self.events.get(event_id)

    def add_rule(self, rule: DelegationRule) -> None:
        self.rules[rule.rule_id] = rule

    def get_rule(self, rule_id: str) -> Optional[DelegationRule]:
        return self.rules.get(rule_id)

    def matching_rule(self, event: WorkflowEvent) -> Optional[DelegationRule]:
        for rule in self.rules.values():
            if rule.matches(event):
                return rule
        return None

    def rules_for(self, agent_id: str, workflow_id: str, authority_value: str) -> list[DelegationRule]:
        return [
            r for r in self.rules.values()
            if r.agent_id == agent_id and r.workflow_id == workflow_id
            and r.authority_class.value == authority_value
        ]

    def all_active_rules_for_agent(self, agent_id: str) -> list[DelegationRule]:
        return [r for r in self.rules.values() if r.agent_id == agent_id and r.active]

    def seen_nonce(self, agent_id: str, nonce: str) -> bool:
        return (agent_id, nonce) in self._nonces

    def mark_nonce(self, agent_id: str, nonce: str) -> None:
        self._nonces.add((agent_id, nonce))

    def claim_nonce(self, agent_id: str, nonce: str) -> bool:
        # Atomic check-and-set under a lock so concurrent threads cannot both
        # claim the same nonce. The SQL store enforces the same invariant via a
        # unique constraint across replicas.
        key = (agent_id, nonce)
        with self._nonce_lock:
            if key in self._nonces:
                return False
            self._nonces.add(key)
            return True

    def to_dict(self) -> dict:
        return {
            "agents": [a.to_dict() for a in self.agents.values()],
            "events": [e.to_dict() for e in self.events.values()],
            "rules": [r.to_dict() for r in self.rules.values()],
        }


class JsonSnapshotStore(InMemoryStore):
    """In-memory store with a JSON snapshot for local persistence/demos."""

    def __init__(self, path: str):
        super().__init__()
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def save(self) -> None:
        with self.path.open("w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2, sort_keys=True)
