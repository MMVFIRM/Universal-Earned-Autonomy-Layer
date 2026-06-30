# Production deployment — what's real and what you must wire up

This document is deliberately blunt about the line between the code in this repo
and a hardened production deployment.

## Real and tested in this repo
- All safety logic (enforcement, ceilings, trust math, guards, SoD, incident
  composition, signed ledger). Covered by 48 passing core tests plus one SQL integration test, including per-defect
  regressions.
- HTTP API with OIDC/JWT verification + RBAC.
- SQLAlchemy store with a Postgres URL; schema auto-created.
- Docker image (non-root, healthcheck) and Compose with Postgres.
- CI (lint + tests across Python 3.10–3.12, plus a Postgres integration job).

## You must provide (and the repo does not fake)
1. **Key custody.** Generate issuer keys with `eal keygen`, then store the
   private key in an HSM/KMS and inject via env/secret. Agent private keys live
   with the agents' runtime, never here.
2. **OIDC IdP.** Set `EAL_OIDC_ISSUER`, `EAL_OIDC_AUDIENCE`, `EAL_OIDC_JWKS_URL`.
   In strict mode dev HMAC auth is refused.
3. **Ledger anchoring.** Provide an `anchor_sink` that posts signed checkpoints
   to immutable external storage. Without it, a holder of the ledger key could
   rewrite history undetected.
4. **PEP isolation.** Ensure the agent cannot reach downstream systems except
   through the PEP. This is the single most important deployment control.
5. **A real database.** Set `EAL_DATABASE_URL` to Postgres. This is now also
   what gives you **shared, atomic capability state** (single-use enforcement
   and revocation across replicas, via `SqlCapabilityStore`). The in-memory
   default is single-replica only; do not run multiple replicas on it.
6. **Load/soak testing and an independent security review.** Not performed here.

### Resolved since v2.1
- Multi-replica single-use enforcement and revocation are handled by the SQL
  capability backend (v2.2). The earlier "single-use only on a single replica"
  constraint no longer applies once a database is configured.


## Suggested rollout
1. Deploy in `strict_mode=true` with all authority classes at Observe-Only.
2. Run in shadow: agents propose, humans decide, nobody auto-executes. Watch the
   `approval_burden_rate` metric and per-class trust accrue.
3. Enact delegation rules only where the recommender clears the severity-coupled
   thresholds, starting with the lowest-risk classes.
4. Keep irreversible/critical classes human-in-the-loop permanently (the
   ceilings enforce this regardless).

## Observability (v3)

- `/metrics` exposes Prometheus counters: decisions by status, incidents,
  recommendations, and the approval-burden rate (the core value signal —
  it should fall as agents earn autonomy). Scrape it on an internal port.
- Logs are structured JSON with a per-request `request_id` (also returned
  in the `x-request-id` header) for correlation with the audit ledger.

## Schema bootstrap (v3)

Run `eal init-db` with `EAL_DATABASE_URL` set to create all tables
(agents, events, delegation_rules, agent_nonces, capability_tokens,
audit_ledger). For production, wrap these DDL operations in Alembic
migrations so schema changes are versioned and reviewable. With a database
configured the audit ledger and capability state are the shared SQL
implementations, so every replica appends to one verifiable chain and
agrees on token consumption/revocation.
