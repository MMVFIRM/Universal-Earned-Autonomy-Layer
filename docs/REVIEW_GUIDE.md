# Review Guide (v3.0.0)

This document is for the human reviewer taking over for final review before any
production deployment. It states what the package claims, what is tested, what
must be verified by a human, and what is explicitly out of scope.

## 1. What this system is

A control plane that grants AI agents progressively more autonomy as they earn
it, and enforces the result. An agent climbs an 8-rung ladder per
`(workflow, authority_class)` by accumulating clean, human-vetted decisions.
High-risk and irreversible authority classes are capped by hard ceilings that no
amount of trust can lift. Decisions are bound to actions by signed, scoped,
single-use capability tokens verified at a Policy Enforcement Point. Everything
is recorded in a signed, hash-chained audit ledger.

Read in this order: `README.md` (orientation), `docs/THREAT_MODEL.md`,
`docs/ENFORCEMENT.md`, `docs/TRUST_MODEL.md`, `docs/AUTONOMY_LADDER.md`,
`docs/ARCHITECTURE.md`.

## 2. Trust boundaries to evaluate

1. Agent ↔ control plane — agent is untrusted; authenticated per-event by
   Ed25519 signature. Verify: `core/control_plane.propose_event`,
   `crypto/signing.py`.
2. Control plane ↔ enforcement — decision bound to action by capability token;
   the PEP is the only path to a side effect. Verify: `enforcement/pep.py`,
   `core/capability.py`, `core/capability_store.py`.
3. Human approver ↔ control plane — OIDC/JWT + RBAC; separation of duties on
   consequential classes; approver identity bound to the authenticated principal,
   not the request body. Verify: `api/auth.py`, `api/server.py`.

## 3. The history this package carries (audit-on-audit)

This is the fourth iteration. Each closed the highest-priority remaining gap.
A reviewer should confirm none have regressed:

- v1 → v2: advisory-only control plane made enforcing; 11 audit findings fixed.
  Regression test per finding: `tests/test_regression_v1_bugs.py`.
- v2.1: token revocation on incident, runtime config wiring, actor binding to
  principal, dev-auth disabled in strict mode. `tests/test_v21_hardening.py`.
- v2.2: shared, atomic capability consumption/revocation so single-use holds
  across replicas. `tests/test_capability_backend.py`.
- v3.0: shared SQL audit ledger and atomic nonce replay protection; operator
  metrics/logging. `tests/test_v3_distributed.py`.

## 4. Test map (what proves what)

| Property | Test file |
|----------|-----------|
| Each v1 defect is fixed | `test_regression_v1_bugs.py` |
| v2.1 hardening (revocation, actor binding, dev-auth, config) | `test_v21_hardening.py` |
| Cross-replica single-use + revocation, atomic single-winner consume | `test_capability_backend.py` |
| Shared ledger (cross-replica, tamper, concurrent-append chained) | `test_v3_distributed.py` |
| Atomic nonce (cross-instance + 10-thread single-winner) | `test_v3_distributed.py` |
| Capability token mint/verify/expiry/revoke/scope | `test_capability.py` |
| Ed25519 sign/verify, canonical bytes | `test_signing.py` |
| Wilson lower bound, clean-vs-modified, replay-safe trust | `test_trust.py` |
| Risk ceilings, SoD set, boundary rules | `test_policy_ceilings.py` |
| requires_approval_if guards, fail-closed | `test_conditions.py` |
| Signed ledger (file) chain + tamper | `test_ledger_signed.py` |
| End-to-end allowed executes / blocked does not | `test_enforcement.py` |
| Recommendation thresholds, incident pinning | `test_core.py` |

Run: `make test` (62 passed, 1 skipped — the skip is the Postgres integration
test, which runs in CI against a real Postgres).

## 5. What a human must verify (cannot be asserted in-repo)

1. **Key custody.** Issuer and agent private keys must live in an HSM/KMS. The
   code operates on key material; it does not store it. Confirm the deployment
   injects keys from a secret store and that `eal keygen` output never lands in
   a repo or image layer.
2. **PEP isolation.** The single most important control: agents must have no
   network path to downstream systems except through the PEP. Confirm network
   policy and that downstream credentials live only in the PEP.
3. **OIDC.** Confirm a real IdP is configured (`EAL_OIDC_*`); dev HMAC auth is
   refused in strict mode.
4. **Ledger anchoring.** Confirm an `anchor_sink` posts signed checkpoints to
   immutable external storage; otherwise a holder of the ledger key could
   rewrite history undetected.
5. **Database HA.** With a database configured, the DB is now load-bearing for
   shared capability state, the audit ledger, and nonce replay protection — not
   just persistence. Confirm replication, backups, and that all replicas share
   one database.
6. **Independent penetration test.** Not performed here.

## 6. Known residual items (tracked, not blocking correctness)

- The YAML policy loader is intentionally thin; code is the source of truth for
  invariants. If policy-as-code must be authoritative, wire the loader and add
  tests that it can only tighten.
- The `anomaly` signal that ladder levels 6/7 react to is supplied by the
  integrator; there is no detector behind it yet.
- `init-db` creates tables via `create_all`; production should wrap schema
  changes in Alembic migrations.
- Per-agent key rotation/lifecycle is not implemented.

## 7. Quick reviewer commands

```bash
make dev                      # editable install with all extras
make test                     # full suite
python -m earned_autonomy.cli demo        # enforced lifecycle, ledger verifies
python -m earned_autonomy.cli sales-demo  # guardrails: SoD, ceilings
EAL_DATABASE_URL=sqlite:///./eal.db python -m earned_autonomy.cli init-db
```
