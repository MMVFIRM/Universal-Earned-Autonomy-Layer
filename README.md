# Universal Earned Autonomy Layer — v2.1

A control plane that grants AI agents **progressively more autonomy as they earn
it**, and — unlike v1 — actually **enforces** the result instead of merely
advising. An agent climbs an 8-rung ladder per (workflow, authority class) by
accumulating clean, human-vetted decisions; high-risk and irreversible actions
are capped by hard ceilings no amount of trust can lift.

This is a ground-up rebuild. The v1 package reasoned over an agent's
self-declared authority, returned a status *string*, and let the agent proceed
regardless. v2.1 binds decisions to actions with signed capability tokens, a
policy enforcement point, Ed25519 agent identity, and a signed audit ledger.

## What "production ready" means here — and what it doesn't

Read this section first; it is the honest part.

**Implemented, tested, and runnable in this repo (the safety-critical core):**
- Ed25519 agent authentication; events are signed and verified (no self-asserted identity).
- Enforcement: a Policy Enforcement Point gates real execution on a capability token verified against the *actual* action. No token, no side effect.
- Risk → maximum-autonomy ceilings; irreversible/critical classes can never auto-execute.
- Statistically honest trust: Wilson lower bound on the *clean*-approval rate, sample sizes coupled to consequence severity, edits counted separately from clean approvals.
- Replay resistance (event nonces + idempotent one-decision-per-event).
- Separation of duties for consequential authority classes.
- Incident handling that *composes* — an incident auto-revokes matching delegation rules, so the agent genuinely drops back to approval-required.
- Signed, hash-chained, checkpointed audit ledger with an external-anchor hook.
- Shared, atomic distributed state (v2.2–v3): with a database configured, capability consumption/revocation, the audit ledger, and nonce replay protection are all atomic and consistent across replicas. Single-use holds under horizontal scaling; all replicas append to one verifiable audit chain.
- Operability: Prometheus `/metrics`, structured JSON logging with per-request ids, and an `eal init-db` schema bootstrap.
- HTTP API with OIDC/JWT auth + RBAC, a SQLAlchemy/Postgres store, an agent SDK, a CLI, Docker/Compose, and CI.
- 62 passing core tests plus one SQL integration test, including one regression test per v1 defect and cross-replica capability/ledger/nonce tests. `make test` is green.

**Deployment-time work this repo cannot do for you (and does not pretend to):**
- Private-key custody in a real HSM/KMS for the issuer and agent keys.
- A real OIDC identity provider (the dev HMAC fallback is for local use and is refused in strict mode when no issuer is configured).
- External anchoring of ledger checkpoints to immutable storage (transparency log / object-lock bucket) — the hook is here; the sink is yours.
- Network isolation of the PEP, load/soak testing, and an independent security review. (HA Postgres is your responsibility, but note the app now *uses* that database for shared capability state, not just persistence.)

In short: the **logic** is production-grade and tested; the **deployment
substrate** (key custody, IdP, anchoring, infra hardening, pen test) is yours to
wire up. `docs/PRODUCTION_DEPLOYMENT.md` and `docs/THREAT_MODEL.md` are explicit
about the boundary.

## Quick start

```bash
make dev          # editable install with [api,sql,dev]
make test         # 48 passing core tests; SQL integration runs when EAL_DATABASE_URL is set
make demo         # end-to-end enforced lifecycle
make sales-demo   # guardrails: free observation, SoD, ceilings
python -m earned_autonomy.cli keygen   # issuer keypair
make serve        # HTTP API on :8000  (requires [api])
```

Minimal in-process usage:

```python
from earned_autonomy.core import EarnedAutonomyControlPlane, ControlPlaneConfig
from earned_autonomy.enforcement import AgentClient, PolicyEnforcementPoint
from earned_autonomy.core.models import AgentIdentity, AuthorityClass, EvidenceItem
from earned_autonomy.crypto import generate_keypair

cp = EarnedAutonomyControlPlane(config=ControlPlaneConfig(strict_mode=True))
pep = PolicyEnforcementPoint(cp.capability_service)
kp = generate_keypair()
cp.register_agent(AgentIdentity(agent_id="a", name="A", owner_id="owner",
    purpose="demo", public_key_hex=kp.public_key_hex, approved_workflows=["w"]))
agent = AgentClient("a", "owner", kp, cp, pep)

event = agent.build_event("w", "stage", "Add a record.",
    AuthorityClass.MODIFY_INTERNAL_RECORD, "queued", "internal record",
    evidence=[EvidenceItem(source="x", claim="y")], confidence=0.95)
packet = agent.propose(event)
# New agent -> approval_required, no capability token issued.
result = agent.execute(event, packet, action=lambda: do_the_real_thing())
# result.allowed is False until autonomy is earned and enacted.
```

## How the v1 audit findings map to v2.1

| # | v1 finding | v2.1 fix |
|---|------------|--------|
| 1 | Advisory only; nothing stopped execution | Capability tokens + PEP gate real execution (`enforcement/pep.py`) |
| 2 | Incident downgrade bypassed by active rule | Incident auto-revokes matching rules (`control_plane.record_incident`) |
| 3 | `requires_approval_if` was dead code | Guards evaluated every action, fail-closed (`core/conditions.py`) |
| 4 | Self-asserted identity, auto-registration | Ed25519-signed events; strict mode rejects unknown/unsigned |
| 5 | Trust gameable by replay | Event nonces + idempotent one-decision-per-event |
| 6 | Declared authority not bound to action | PEP verifies token against the actual action |
| 7 | Default level = Execute-with-approval | Default = Observe-Only; observation is free |
| 8 | No risk ceiling; irreversible auto-delegable | `MAX_AUTONOMY_BY_RISK` ceilings, enforced everywhere |
| 9 | Owner could approve own agent | Separation of duties for consequential classes |
| 10 | Modified-and-approved counted as success | Clean vs modified tracked separately; Wilson LB on clean only |
| 11 | Ladder 5/6/7 identical; brittle keyword classifier | Distinct rung semantics; word-boundary, advisory-only classifier |
| 12 | Ledger tamper-evident only vs accidents | Ed25519-signed chain + checkpoints + anchor hook |

See `docs/` for the threat model, enforcement design, trust model, and the full
ladder semantics.

## License
Apache-2.0.
