from __future__ import annotations

from typing import Callable, Dict, List

from .models import WorkflowEvent

# v2 fix: in v1 the `requires_approval_if` predicates on every delegation rule
# were never read by any code path — pure decoration. Here we give each named
# predicate a real implementation. The policy engine evaluates them before a
# delegation rule is allowed to grant autonomy; if ANY fires, the action is
# forced back to human approval.

GuardFn = Callable[[WorkflowEvent], bool]


def _missing_source_evidence(event: WorkflowEvent) -> bool:
    return len(event.evidence) == 0


def _low_confidence(event: WorkflowEvent, threshold: float = 0.7) -> bool:
    return event.confidence < threshold


def _outside_known_workflow(event: WorkflowEvent) -> bool:
    approved = event.metadata.get("_approved_workflows", [])
    return bool(approved) and event.workflow_id not in approved


def _external_effect(event: WorkflowEvent) -> bool:
    return event.metadata.get("external_effect") is True


def _irreversible(event: WorkflowEvent) -> bool:
    return event.metadata.get("irreversible") is True


def _anomaly_detected(event: WorkflowEvent) -> bool:
    return event.metadata.get("anomaly") is True


# `policy_boundary_matched` is special: it is decided by the policy engine, not
# by the event alone, so it is injected via metadata before evaluation.
def _policy_boundary_matched(event: WorkflowEvent) -> bool:
    return event.metadata.get("_policy_boundary_matched") is True


GUARDS: Dict[str, GuardFn] = {
    "missing_source_evidence": _missing_source_evidence,
    "low_confidence": _low_confidence,
    "outside_known_workflow": _outside_known_workflow,
    "external_effect": _external_effect,
    "irreversible": _irreversible,
    "anomaly_detected": _anomaly_detected,
    "policy_boundary_matched": _policy_boundary_matched,
}


def evaluate_guards(predicates: List[str], event: WorkflowEvent) -> List[str]:
    """Return the list of named predicates that fired for this event.

    Unknown predicate names are treated as fired (fail-closed): a rule that
    references a guard we cannot evaluate must not grant autonomy on the
    assumption it is satisfied.
    """
    triggered: List[str] = []
    for name in predicates:
        fn = GUARDS.get(name)
        if fn is None:
            triggered.append(f"{name}:unknown_guard_fail_closed")
            continue
        if fn(event):
            triggered.append(name)
    return triggered
