from pathlib import Path

import jwt
from fastapi.testclient import TestClient

from earned_autonomy.api.server import build_control_plane_from_settings, create_app
from earned_autonomy.config import Settings
from earned_autonomy.core.models import (
    ApprovalOutcome,
    AuthorityClass,
    AutonomyLevel,
    DelegationRule,
    EvidenceItem,
)
from earned_autonomy.crypto import generate_keypair
from earned_autonomy.enforcement import AgentClient, PolicyEnforcementPoint
from earned_autonomy.storage.sql import SqlStore
from helpers import make_agent_with_key, make_cp, signed_event


def test_incident_revokes_preexisting_capability_token():
    cp = make_cp()
    kp = make_agent_with_key(cp, workflows=("w",))
    pep = PolicyEnforcementPoint(cp.capability_service)
    client = AgentClient("lead_finder", "sales_rep_01", kp, cp, pep)
    rule = DelegationRule(
        rule_name="auto internal",
        workflow_id="w",
        agent_id="lead_finder",
        authority_class=AuthorityClass.MODIFY_INTERNAL_RECORD,
        autonomy_level=AutonomyLevel.CONDITIONAL_AUTONOMY,
        conditions={"evidence_required": True},
    )
    cp.approve_delegation_rule(rule, approver_id="manager")
    ev = client.build_event(
        "w", "stage", "Add lead", AuthorityClass.MODIFY_INTERNAL_RECORD,
        "Lead queued", "Internal record created",
        evidence=[EvidenceItem(source="web", claim="valid")], confidence=0.95,
        metadata={"evidence_required": True},
    )
    packet = client.propose(ev)
    assert packet["capability_token"] is not None

    incident = cp.record_incident(
        "lead_finder", "w", AuthorityClass.MODIFY_INTERNAL_RECORD,
        reason="bad write", actor_id="admin",
    )
    assert incident["revoked_capability_tokens"] >= 1

    ran = {"value": False}
    result = client.execute(
        ev, packet, action=lambda: ran.update(value=True),
        action_context={"evidence_required": True},
    )
    assert result.allowed is False
    assert "revoked" in result.reason
    assert ran["value"] is False


def test_manual_rule_revocation_revokes_preexisting_tokens():
    cp = make_cp()
    kp = make_agent_with_key(cp, workflows=("w",))
    pep = PolicyEnforcementPoint(cp.capability_service)
    client = AgentClient("lead_finder", "sales_rep_01", kp, cp, pep)
    rule = cp.approve_delegation_rule(DelegationRule(
        rule_name="auto internal",
        workflow_id="w",
        agent_id="lead_finder",
        authority_class=AuthorityClass.MODIFY_INTERNAL_RECORD,
        autonomy_level=AutonomyLevel.CONDITIONAL_AUTONOMY,
        conditions={"evidence_required": True},
    ), approver_id="manager")
    ev = client.build_event(
        "w", "stage", "Add lead", AuthorityClass.MODIFY_INTERNAL_RECORD,
        "Lead queued", "Internal record created",
        evidence=[EvidenceItem(source="web", claim="valid")], confidence=0.95,
        metadata={"evidence_required": True},
    )
    packet = client.propose(ev)
    assert packet["capability_token"] is not None
    assert cp.revoke_delegation_rule(rule.rule_id, actor_id="admin", reason="tighten policy") is True
    result = client.execute(ev, packet, action=lambda: "would execute", action_context={"evidence_required": True})
    assert result.allowed is False
    assert "revoked" in result.reason


def test_settings_factory_uses_sql_store_ledger_path_and_issuer_keys(tmp_path: Path):
    from earned_autonomy.core.capability_store import SqlCapabilityStore
    from earned_autonomy.core.ledger import AuditLedger
    from earned_autonomy.core.ledger_sql import SqlAuditLedger

    kp = generate_keypair()
    db = tmp_path / "eal.db"
    settings = Settings(
        strict_mode=True,
        database_url=f"sqlite:///{db}",
        issuer_private_key_hex=kp.private_key_hex,
        issuer_public_key_hex=kp.public_key_hex,
    )
    cp = build_control_plane_from_settings(settings)
    assert isinstance(cp.store, SqlStore)
    # v3: with a database configured, the audit ledger and capability state are
    # the shared SQL implementations, not per-process file/memory ones.
    assert isinstance(cp.ledger, SqlAuditLedger)
    assert isinstance(cp.capability_service.state, SqlCapabilityStore)
    assert cp.config.allowed_capability_ttl_seconds == settings.capability_ttl_seconds

    # When no database is configured, ledger_path drives a file-backed ledger.
    ledger_file = tmp_path / "audit.log"
    file_settings = Settings(
        strict_mode=False,
        database_url="memory",
        ledger_path=str(ledger_file),
        issuer_private_key_hex=kp.private_key_hex,
        issuer_public_key_hex=kp.public_key_hex,
    )
    file_cp = build_control_plane_from_settings(file_settings)
    assert isinstance(file_cp.ledger, AuditLedger)
    assert file_cp.ledger.path == ledger_file


def test_api_binds_decision_actor_to_authenticated_principal_not_body():
    cp = make_cp()
    kp = make_agent_with_key(cp)
    ev = signed_event(kp)
    cp.propose_event(ev)
    settings = Settings(strict_mode=False, dev_auth_secret="dev-secret-with-at-least-32-bytes!!")
    app = create_app(control_plane=cp, settings=settings)
    client = TestClient(app)
    token = jwt.encode({"sub": "actual_approver", "roles": ["approver"]}, "dev-secret-with-at-least-32-bytes!!", algorithm="HS256")
    res = client.post(
        "/decisions",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "event_id": ev.event_id,
            "approver_id": "forged_other_person",
            "outcome": ApprovalOutcome.APPROVED.value,
            "approver_role": "manager",
        },
    )
    assert res.status_code == 200, res.text
    assert res.json()["decision"]["approver_id"] == "actual_approver"


def test_strict_mode_refuses_dev_hmac_without_oidc():
    settings = Settings(strict_mode=True, dev_auth_secret="dev-secret-with-at-least-32-bytes!!")
    # provide explicit control plane so create_app does not require issuer keys for this auth check
    app = create_app(control_plane=make_cp(), settings=settings)
    client = TestClient(app)
    token = jwt.encode({"sub": "admin", "roles": ["auditor"]}, "dev-secret-with-at-least-32-bytes!!", algorithm="HS256")
    res = client.get("/audit/verify", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 401
    assert "dev auth is disabled in strict mode" in res.text
