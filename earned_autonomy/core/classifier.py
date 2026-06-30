from __future__ import annotations

import re
from typing import Protocol

from .models import ConsequenceClass, RiskLevel, WorkflowEvent
from .ontology import base_risk_for, consequences_for, max_risk


class Classifier(Protocol):
    """Pluggable classifier interface.

    v1 hard-wired a substring keyword scan into the decision path. v2 makes the
    classifier a swappable component: an enterprise can drop in a model-backed
    classifier, but the default stays rule-based and inspectable. Critically,
    the classifier is *advisory* — it can only RAISE risk. The binding
    constraints come from the authority ontology and policy ceilings, never
    from lexical guessing.
    """

    def classify(
        self, event: WorkflowEvent
    ) -> tuple[list[ConsequenceClass], RiskLevel, list[str]]: ...


class RuleBasedClassifier:
    """Transparent default classifier.

    Risk derives primarily from the (trusted) authority class and structured
    metadata. The lexical layer is a secondary signal that can only escalate,
    uses word-boundary matching (not substrings, which caused v1 false hits
    like 'access' inside other words), and reports every match instead of
    breaking on the first.
    """

    # Word-stem patterns. \b anchors avoid the v1 substring problem. Stems
    # catch inflections (delete/deleting/deletion) without a giant word list.
    HIGH_RISK_PATTERNS = [
        r"\bdiscount", r"\brefund", r"\bcontract", r"\blegal", r"\bguarantee",
        r"\bdelet", r"\bpurg", r"\bdrop\b", r"\btruncat", r"\bwipe",
        r"\bproduction\b", r"\bpayment", r"\bwire\b", r"\btransfer",
        r"\bterminat", r"\bdisburse", r"\bcredential", r"\bprivilege",
        r"\broot\b", r"\bsudo\b",
    ]

    def __init__(self) -> None:
        self._patterns = [(p, re.compile(p, re.IGNORECASE)) for p in self.HIGH_RISK_PATTERNS]

    def classify(
        self, event: WorkflowEvent
    ) -> tuple[list[ConsequenceClass], RiskLevel, list[str]]:
        consequences = list(consequences_for(event.authority_requested))
        risk = base_risk_for(event.authority_requested)
        reasons = [f"Base risk from authority class: {event.authority_requested.value}"]

        text = " ".join(
            [
                event.intent,
                event.proposed_next_state,
                event.expected_effect,
                " ".join(item.claim for item in event.evidence),
            ]
        )

        for raw, pattern in self._patterns:
            if pattern.search(text):
                risk = max_risk(risk, RiskLevel.HIGH)
                reasons.append(f"High-risk language matched: /{raw}/")

        if event.metadata.get("external_effect") is True and ConsequenceClass.EXTERNAL_FACING not in consequences:
            consequences.append(ConsequenceClass.EXTERNAL_FACING)
            risk = max_risk(risk, RiskLevel.MEDIUM)
            reasons.append("Metadata indicates external effect")

        if event.metadata.get("irreversible") is True and ConsequenceClass.IRREVERSIBLE not in consequences:
            consequences.append(ConsequenceClass.IRREVERSIBLE)
            risk = max_risk(risk, RiskLevel.CRITICAL)
            reasons.append("Metadata indicates irreversible effect")

        if event.confidence < 0.5 and event.requires_execution:
            risk = max_risk(risk, RiskLevel.MEDIUM)
            reasons.append("Low-confidence execution request")

        if not event.evidence and event.requires_execution:
            risk = max_risk(risk, RiskLevel.MEDIUM)
            reasons.append("Execution requested with no evidence")

        seen = set()
        unique = []
        for c in consequences:
            if c.value not in seen:
                seen.add(c.value)
                unique.append(c)
        return unique, risk, reasons
