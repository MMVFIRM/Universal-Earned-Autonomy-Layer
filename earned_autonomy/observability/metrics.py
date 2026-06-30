from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Dict


@dataclass
class GovernanceMetrics:
    """In-process governance counters. In production these would export to
    Prometheus/OpenTelemetry; the interface is kept trivial so a real exporter
    can wrap it. These exist to answer the ENTERPRISE_READINESS question
    'can approval-burden reduction be measured?' quantitatively.
    """
    decisions: Counter = field(default_factory=Counter)
    enforcement: Counter = field(default_factory=Counter)
    incidents: int = 0
    recommendations: int = 0

    def record_decision(self, status: str) -> None:
        self.decisions[status] += 1

    def record_enforcement(self, kind: str) -> None:
        self.enforcement[kind] += 1

    def record_incident(self) -> None:
        self.incidents += 1

    def record_recommendation(self) -> None:
        self.recommendations += 1

    @property
    def approval_burden_rate(self) -> float:
        """Fraction of decisions that needed a human. Falling over time is the
        core value signal of the product."""
        total = sum(self.decisions.values())
        if total == 0:
            return 0.0
        human = self.decisions.get("approval_required", 0) + self.decisions.get("escalate", 0)
        return human / total

    def snapshot(self) -> Dict[str, object]:
        return {
            "decisions": dict(self.decisions),
            "enforcement": dict(self.enforcement),
            "incidents": self.incidents,
            "recommendations": self.recommendations,
            "approval_burden_rate": self.approval_burden_rate,
        }
