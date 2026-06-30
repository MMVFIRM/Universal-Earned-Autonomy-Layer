# Changelog

## 3.0.0 — Consolidation for review: all shared state is shared and atomic

v3 closes the two remaining places where distributed state was not consistent
across replicas, so the "shared and atomic" property now holds uniformly (tokens,
ledger, and replay protection). It also adds the operator surface a human
reviewer and an ops team expect.

### Added
- **Shared SQL audit ledger** (`core/ledger_sql.py`): all replicas append to one
  hash-chained, signed, verifiable chain. Appends are serialized — by a Postgres
  advisory transaction lock, or by `BEGIN IMMEDIATE` on SQLite — so sequence
  numbers and previous-hash links stay consistent under concurrent writers. The
  settings factory selects it automatically when a database is configured.
- **Atomic nonce replay protection**: `Store.claim_nonce` replaces the
  `seen_nonce`/`mark_nonce` check-then-act. It is a single check-and-set (unique
  constraint in SQL, lock in memory), closing the cross-replica TOCTOU window
  where two replicas could both accept the same event.
- **Governance metrics + `/metrics`**: decisions, incidents, and recommendations
  are recorded on the control plane and exposed in Prometheus text format.
- **Structured JSON logging** with a per-request `request_id` carried on a
  context var and echoed in an `x-request-id` response header.
- **`eal init-db`**: deterministic schema bootstrap for all SQL tables, with a
  pointer to wrapping the DDL in Alembic for production.
- `tests/test_v3_distributed.py`: shared-ledger cross-replica + tamper +
  concurrent-append-stays-chained, atomic-nonce cross-instance + 10-thread
  single-winner, and the metrics endpoint. 62 tests pass, 1 skipped.

### Changed
- `build_control_plane_from_settings` now wires the SQL ledger and SQL capability
  state whenever a database is configured; the file/in-memory ledger remains the
  default for single-instance / `database_url=memory`.
- The v2.1 factory test was updated to assert the new (shared SQL) ledger and
  capability backends when a database is configured, plus the file-ledger
  fallback when it is not.

### Caveat resolved
- The audit ledger is no longer per-process when a database is configured; the
  earlier "each replica produces an independent chain" note from v2.2 is closed.

## 2.2.0 — Shared atomic capability state

Closes the multi-replica capability gap surfaced in the v2.1 audit: under
horizontal scaling a `single_use=True` token consumed on one replica was
re-accepted on another, and a revocation processed on one replica was invisible
to the rest. The once-only guarantee silently degraded to once-per-replica.

### Added
- `core/capability_store.py`: a pluggable `CapabilityStateStore` with two
  implementations.
  - `InMemoryCapabilityStore` (default): single-process, thread-safe.
  - `SqlCapabilityStore` (Postgres/SQLite): makes consume, revoke, and
    revoke-by-scope atomic and shared across replicas.
- Atomic `try_consume`: a single conditional UPDATE
  (`SET consumed=1 WHERE token_id=:id AND consumed=0 AND revoked=0`) whose row
  lock yields exactly one winner across all replicas — no read-then-write TOCTOU
  window. The same predicate honors a concurrent revoke.
- `CapabilityService.purge_expired()` to bound storage growth (safe: expired
  tokens are rejected before consumption).
- `tests/test_capability_backend.py`: proves cross-replica single-use rejection,
  cross-replica revocation, scope precision, and exactly-one-winner under real
  8-thread contention.

### Changed
- `CapabilityService` delegates all consumption/revocation state to the store
  (constructor gains an optional `state_store`). Default behavior is unchanged;
  the in-memory store is selected automatically for `database_url=memory`.
- `build_control_plane_from_settings` wires a `SqlCapabilityStore` whenever a
  database is configured, so a multi-replica deployment gets shared token state
  with no extra wiring.

### Caveat now removed
- v2.1's "single-use is only single-use on a single replica" constraint no
  longer applies when a database is configured. Remaining production
  prerequisites are unchanged: KMS/HSM key custody, OIDC, external ledger
  anchoring, and an independent security review.

## 2.1.0 — Enterprise hardening pass

### Fixed
- Revokes outstanding capability tokens when an incident is recorded or a matching delegation rule is manually revoked, preventing pre-incident/pre-revocation tokens from executing during their TTL window.
- Wires `EAL_DATABASE_URL`, `EAL_LEDGER_PATH`, issuer keys, and capability TTL settings into the FastAPI runtime. The v2.0 API factory exposed these settings but silently ran on generated in-memory state.
- Binds API approval, delegation-rule approval, and incident actor IDs to the authenticated principal instead of trusting caller-supplied body fields.
- Disables dev-HMAC admin auth in strict mode when OIDC is not configured.

### Added
- 5 hardening regression tests covering token revocation, deployment settings, API actor binding, and strict-mode auth behavior.

## 2.0.0 — Enforced rebuild

Complete redesign in response to the v1 security audit. Every change below maps
to a numbered finding in that audit.

### Added
- **Enforcement layer** (#1, #6): `CapabilityService` mints short-lived, scoped,
  single-use Ed25519-signed tokens; `PolicyEnforcementPoint` verifies a token
  against the *actual* action before invoking the real tool. Decisions that are
  not ALLOWED issue no token, so there is nothing to execute with.
- **Agent identity** (#4): events are Ed25519-signed; identity is a public key.
  Strict mode rejects unsigned, forged, and unknown-agent events; no silent
  auto-registration.
- **Risk ceilings** (#8): `MAX_AUTONOMY_BY_RISK` caps autonomy per authority
  class. Critical/irreversible classes top out at Execute-With-Approval.
- **Separation of duties** (#9): consequential classes require an approver who
  is not the agent owner, at both decision and delegation-rule approval.
- **Statistically honest trust** (#5, #10): Wilson lower bound on the clean
  approval rate; minimum sample sizes coupled to consequence severity; clean and
  modified approvals tracked separately.
- **Signed audit ledger** (#12): hash-chained + Ed25519-signed records, sequence
  numbers, periodic signed checkpoints, external-anchor hook.
- HTTP API (FastAPI) with OIDC/JWT auth + RBAC; SQLAlchemy/Postgres store; agent
  SDK; CLI; Docker/Compose; GitHub Actions CI; regression test per v1 defect.

### Changed
- **Default autonomy** is Observe-Only (0), not Execute-With-Approval (3) (#7).
  Observation and other non-state actions are allowed without approval.
- **`requires_approval_if` guards are now evaluated** every action and
  fail-closed on unknown predicates (#3).
- **Ladder rungs 4–7 have distinct runtime semantics** (#11): sampling,
  conditional, exception-based (anomaly escalates), delegated (periodic
  attestation).
- **Classifier** is a pluggable interface; the default uses word-boundary
  matching, reports all matches, and can only raise risk — never the sole gate.

### Fixed
- Incident downgrade no longer bypassed by a still-active delegation rule (#2):
  incidents auto-revoke matching rules and revoke issued capabilities.
- Replay of decisions against a single event can no longer inflate trust (#5).
