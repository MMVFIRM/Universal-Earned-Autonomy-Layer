from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional

from ..core.capability import CapabilityService
from ..core.models import AuthorityClass, CapabilityToken


class EnforcementError(Exception):
    """Raised when an action is attempted without valid authority."""


@dataclass
class ExecutionResult:
    allowed: bool
    reason: str
    token_id: Optional[str]
    output: Any = None


class PolicyEnforcementPoint:
    """The PEP sits at the integration boundary — wherever the agent actually
    touches a downstream system (Salesforce, Gmail, a database, a payment API).

    The agent cannot execute a state-changing action by itself; it must route
    the call through `execute`, presenting the capability token the control
    plane issued. The PEP verifies the token against the *actual* action it is
    about to perform, then and only then invokes the real tool. A "blocked" or
    "approval_required" decision yields no token, so there is nothing to present
    and the PEP refuses.

    This is the structural answer to the v1 critique: in v1 the control plane
    returned a status string and nothing stopped the agent from proceeding. Here
    execution is physically wrapped, and the token binds the granted scope to
    the performed action.
    """

    def __init__(self, capability_service: CapabilityService, on_event: Optional[Callable[[dict], None]] = None):
        self.capabilities = capability_service
        self.on_event = on_event

    def execute(
        self,
        token: Optional[CapabilityToken],
        agent_id: str,
        workflow_id: str,
        authority_class: AuthorityClass,
        action: Callable[[], Any],
        action_context: Optional[Dict[str, Any]] = None,
    ) -> ExecutionResult:
        if token is None:
            self._emit("enforcement.denied", agent_id, workflow_id, authority_class, "no capability token")
            return ExecutionResult(False, "no capability token presented", None)

        result = self.capabilities.verify_for_action(
            token=token,
            action_agent_id=agent_id,
            action_workflow_id=workflow_id,
            action_authority_class=authority_class,
            action_context=action_context,
        )
        if not result.ok:
            self._emit("enforcement.denied", agent_id, workflow_id, authority_class, result.reason)
            return ExecutionResult(False, result.reason, result.token_id)

        output = action()
        self._emit("enforcement.allowed", agent_id, workflow_id, authority_class, "executed")
        return ExecutionResult(True, "executed under valid capability", result.token_id, output)

    def _emit(self, kind, agent_id, workflow_id, authority_class, reason):
        if self.on_event:
            self.on_event({
                "kind": kind, "agent_id": agent_id, "workflow_id": workflow_id,
                "authority_class": authority_class.value, "reason": reason,
            })
