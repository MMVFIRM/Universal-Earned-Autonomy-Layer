"""FastAPI surface for the Earned Autonomy control plane.

Endpoints map to control-plane operations. Authentication is enforced via the
Authenticator dependency; mutating endpoints additionally require a role. Agent
event proposals are authenticated by the Ed25519 signature INSIDE the event (the
control plane verifies it), so the proposing caller's bearer token only needs to
be a valid gateway principal, not the agent itself.

Run: uvicorn earned_autonomy.api.server:create_app --factory
"""
from __future__ import annotations

from typing import Optional

try:
    from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
except ImportError as exc:  # pragma: no cover - optional dep
    raise RuntimeError("API extras not installed. Install with: pip install -e '.[api]'") from exc

from ..config import Settings
from ..core import (
    AuthenticationError,
    ControlPlaneError,
    EarnedAutonomyControlPlane,
    SeparationOfDutiesError,
)
from ..core.control_plane import ControlPlaneConfig
from ..core.capability import CapabilityService
from ..core.ledger import AuditLedger
from ..crypto import generate_keypair
from ..storage import InMemoryStore, SqlStore
from ..core.models import (
    AgentIdentity,
    ApprovalDecision,
    ApprovalOutcome,
    AuthorityClass,
    AutonomyLevel,
    DelegationRule,
    EvidenceItem,
    WorkflowEvent,
    WorkflowEventType,
)
from .auth import AuthError, Authenticator, Principal, require_role
from .schemas import (
    DecisionIn,
    DelegationRuleIn,
    IncidentIn,
    ProposeEventIn,
    RegisterAgentIn,
)


def build_control_plane_from_settings(settings: Settings) -> EarnedAutonomyControlPlane:
    """Build a control plane from deployment settings.

    v2.0 exposed database_url, ledger_path, issuer keys, and TTL settings but
    the API factory ignored them, so Docker/production envs silently ran on
    ephemeral in-memory state. v2.1 wires the settings into the actual runtime.
    """
    if settings.database_url and settings.database_url != "memory":
        if SqlStore is None:  # pragma: no cover - optional dependency guard
            raise RuntimeError("SQL store requested but SQL extras are not installed")
        store = SqlStore(settings.database_url)
    else:
        store = InMemoryStore()

    if settings.issuer_private_key_hex and settings.issuer_public_key_hex:
        issuer_private = settings.issuer_private_key_hex
        issuer_public = settings.issuer_public_key_hex
    else:
        if settings.strict_mode:
            raise RuntimeError("strict_mode requires EAL_ISSUER_PRIVATE_KEY_HEX and EAL_ISSUER_PUBLIC_KEY_HEX")
        kp = generate_keypair()
        issuer_private, issuer_public = kp.private_key_hex, kp.public_key_hex

    # Audit ledger: a shared SQL chain when a database is configured (so all
    # replicas append to one verifiable chain), else the file/in-memory ledger.
    if settings.database_url and settings.database_url != "memory":
        from ..core.ledger_sql import SqlAuditLedger
        if SqlAuditLedger is None:  # pragma: no cover - optional dependency guard
            raise RuntimeError("SQL ledger requested but SQL extras are not installed")
        ledger = SqlAuditLedger(issuer_private, issuer_public, settings.database_url)
    else:
        ledger = AuditLedger(issuer_private, issuer_public, path=settings.ledger_path)

    # Shared, atomic capability state when a database is configured, so the
    # single-use guarantee and revocation hold across replicas. Falls back to
    # the in-process store only for single-instance / in-memory deployments.
    capability_state = None
    if settings.database_url and settings.database_url != "memory":
        from ..core.capability_store import SqlCapabilityStore
        if SqlCapabilityStore is None:  # pragma: no cover - optional dependency guard
            raise RuntimeError("SQL capability store requested but SQL extras are not installed")
        capability_state = SqlCapabilityStore(settings.database_url)
    capability_service = CapabilityService(issuer_private, issuer_public, state_store=capability_state)
    return EarnedAutonomyControlPlane(
        store=store,
        ledger=ledger,
        capability_service=capability_service,
        config=ControlPlaneConfig(
            strict_mode=settings.strict_mode,
            allowed_capability_ttl_seconds=settings.capability_ttl_seconds,
            sampled_capability_ttl_seconds=settings.capability_ttl_seconds,
        ),
    )


def create_app(
    control_plane: Optional[EarnedAutonomyControlPlane] = None,
    settings: Optional[Settings] = None,
) -> FastAPI:
    settings = settings or Settings.from_env()
    cp = control_plane or build_control_plane_from_settings(settings)
    authenticator = Authenticator(settings)
    app = FastAPI(title="Earned Autonomy Layer", version="3.0.0")

    def principal(authorization: Optional[str] = Header(default=None)) -> Principal:
        try:
            return authenticator.authenticate(authorization)
        except AuthError as exc:
            raise HTTPException(status_code=401, detail=str(exc))

    import logging
    import time
    import uuid

    from ..logging_config import configure_logging, log_event, request_id_var

    configure_logging(settings.log_level)
    _logger = logging.getLogger("eal.api")

    @app.middleware("http")
    async def request_context(request: Request, call_next):
        rid = request.headers.get("x-request-id") or uuid.uuid4().hex
        token = request_id_var.set(rid)
        start = time.monotonic()
        try:
            response = await call_next(request)
        finally:
            request_id_var.reset(token)
        elapsed_ms = round((time.monotonic() - start) * 1000, 2)
        log_event(
            _logger, logging.INFO, "request",
            method=request.method, path=request.url.path, elapsed_ms=elapsed_ms,
        )
        response.headers["x-request-id"] = rid
        return response

    @app.get("/metrics")
    def metrics():
        # Prometheus text exposition format. Unauthenticated by convention so a
        # scraper can reach it; expose it only on an internal network/port.
        snap = cp.metrics.snapshot()
        lines = [
            "# HELP eal_build_info Build info.",
            "# TYPE eal_build_info gauge",
            'eal_build_info{version="3.0.0"} 1',
            "# HELP eal_decisions_total Policy decisions by status.",
            "# TYPE eal_decisions_total counter",
        ]
        for status, count in snap["decisions"].items():
            lines.append(f'eal_decisions_total{{status="{status}"}} {count}')
        lines += [
            "# HELP eal_enforcement_total Enforcement outcomes.",
            "# TYPE eal_enforcement_total counter",
        ]
        for kind, count in snap["enforcement"].items():
            lines.append(f'eal_enforcement_total{{kind="{kind}"}} {count}')
        lines += [
            "# HELP eal_incidents_total Incidents recorded.",
            "# TYPE eal_incidents_total counter",
            f"eal_incidents_total {snap['incidents']}",
            "# HELP eal_recommendations_total Autonomy recommendations produced.",
            "# TYPE eal_recommendations_total counter",
            f"eal_recommendations_total {snap['recommendations']}",
            "# HELP eal_approval_burden_rate Fraction of decisions needing a human.",
            "# TYPE eal_approval_burden_rate gauge",
            f"eal_approval_burden_rate {snap['approval_burden_rate']}",
        ]
        return Response("\n".join(lines) + "\n", media_type="text/plain; version=0.0.4")

    @app.get("/healthz")
    def healthz():
        return {"status": "ok", "version": "3.0.0", "strict_mode": settings.strict_mode}

    @app.get("/audit/verify")
    def audit_verify(p: Principal = Depends(principal)):
        require_role_or_403(p, "auditor")
        return {"verified": cp.ledger.verify(), "records": len(cp.ledger.records())}

    @app.post("/agents")
    def register_agent(body: RegisterAgentIn, p: Principal = Depends(principal)):
        require_role_or_403(p, "agent_admin")
        try:
            agent = cp.register_agent(AgentIdentity(**body.model_dump()))
        except AuthenticationError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        return agent.to_dict()

    @app.post("/events")
    def propose_event(body: ProposeEventIn, p: Principal = Depends(principal)):
        require_role_or_403(p, "agent_gateway")
        event = WorkflowEvent(
            agent_id=body.agent_id, human_owner_id=body.human_owner_id, workflow_id=body.workflow_id,
            workflow_stage=body.workflow_stage, event_type=WorkflowEventType(body.event_type),
            intent=body.intent, authority_requested=AuthorityClass(body.authority_requested),
            proposed_next_state=body.proposed_next_state, expected_effect=body.expected_effect,
            evidence=[EvidenceItem(**e.model_dump()) for e in body.evidence],
            confidence=body.confidence, requires_execution=body.requires_execution,
            nonce=body.nonce, signature=body.signature, metadata=body.metadata,
        )
        try:
            return cp.propose_event(event)
        except AuthenticationError as exc:
            raise HTTPException(status_code=401, detail=str(exc))

    @app.post("/decisions")
    def submit_decision(body: DecisionIn, p: Principal = Depends(principal)):
        require_role_or_403(p, "approver")
        decision = ApprovalDecision(
            event_id=body.event_id, approver_id=p.subject,
            outcome=ApprovalOutcome(body.outcome), approver_role=body.approver_role,
            rationale=body.rationale, modifications=body.modifications,
        )
        try:
            return cp.submit_decision(decision)
        except SeparationOfDutiesError as exc:
            raise HTTPException(status_code=409, detail=str(exc))
        except ControlPlaneError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    @app.post("/delegation-rules")
    def approve_rule(body: DelegationRuleIn, p: Principal = Depends(principal)):
        require_role_or_403(p, "autonomy_admin")
        rule = DelegationRule(
            rule_name=body.rule_name, workflow_id=body.workflow_id, agent_id=body.agent_id,
            authority_class=AuthorityClass(body.authority_class),
            autonomy_level=AutonomyLevel(body.autonomy_level), conditions=body.conditions,
            requires_approval_if=body.requires_approval_if, sample_rate=body.sample_rate,
        )
        try:
            return cp.approve_delegation_rule(rule, p.subject, body.approver_role).to_dict()
        except (SeparationOfDutiesError, ControlPlaneError) as exc:
            raise HTTPException(status_code=409, detail=str(exc))

    @app.post("/incidents")
    def record_incident(body: IncidentIn, p: Principal = Depends(principal)):
        require_role_or_403(p, "autonomy_admin")
        return cp.record_incident(
            body.agent_id, body.workflow_id, AuthorityClass(body.authority_class),
            body.reason, p.subject,
        )

    @app.get("/agents/{agent_id}/autonomy-map")
    def autonomy_map(agent_id: str, p: Principal = Depends(principal)):
        require_role_or_403(p, "auditor")
        try:
            return cp.autonomy_map(agent_id)
        except ControlPlaneError as exc:
            raise HTTPException(status_code=404, detail=str(exc))

    return app


def require_role_or_403(principal: Principal, role: str) -> None:
    try:
        require_role(principal, role)
    except AuthError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
