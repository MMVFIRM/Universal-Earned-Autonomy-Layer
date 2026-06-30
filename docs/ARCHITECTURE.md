# Architecture

```
earned_autonomy/
  crypto/        canonical serialization + Ed25519 sign/verify
  core/
    models       domain types, enums, signed events, Wilson-LB trust stats
    ontology     authority→consequence, base risk, risk→max-autonomy ceiling
    classifier   pluggable, advisory, word-boundary risk classifier
    conditions   requires_approval_if guard evaluator (fail-closed)
    policy       boundary rules + ceiling enforcement + ladder semantics
    trust        idempotent delegation memory (replay-safe)
    recommendations  severity-coupled, ceiling-clamped, Wilson-LB recommender
    capability   capability-token mint/verify/revoke
    ledger       signed hash-chained audit ledger (file/in-memory)
    ledger_sql   shared SQL audit ledger (one verifiable chain across replicas)
    capability_store  pluggable token state; in-memory + atomic SQL backend
    control_plane orchestration: auth, replay, enforcement, incident composition
  enforcement/
    pep          Policy Enforcement Point (gates real execution on a token)
    sdk          agent client (signs events, executes through the PEP)
  storage/       Store interface; in-memory + JSON; SQLAlchemy/Postgres adapter
  api/           FastAPI server, OIDC/JWT auth + RBAC, schemas
  observability/ governance metrics (approval-burden rate, etc.)
  config         env-driven settings
  logging_config structured JSON logging + per-request id
  cli            keygen / demo / serve
```

## Request lifecycle (propose → execute)
1. Agent builds an event and signs it (SDK).
2. `propose_event`: verify signature → reject unknown/unsigned → check nonce →
   classify → look up matching delegation rule → policy evaluate (ceiling,
   guards, ladder) → mint capability token iff ALLOWED/SAMPLE_REVIEW → append a
   signed audit record.
3. Agent calls `PEP.execute` with the token; the PEP verifies it against the
   actual action and runs the real tool only if valid.

## Decision ordering (each step only restricts)
hard boundary rules → ceiling clamp → guard evaluation → ladder semantics.

## Distributed state (v2.2–v3)

When a database is configured, three pieces of state that must be globally
consistent are backed by SQL and made atomic:

- **Capability consumption/revocation** (`capability_store.py`): a single
  conditional UPDATE yields exactly one consume winner across replicas.
- **Audit ledger** (`ledger_sql.py`): appends are serialized (Postgres
  advisory lock / SQLite BEGIN IMMEDIATE) so the hash chain stays valid
  under concurrent writers; every replica verifies the same chain.
- **Nonce replay protection** (`storage/sql.py::claim_nonce`): a single
  insert against a unique constraint; the loser is reported as a replay.
