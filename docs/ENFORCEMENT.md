# Enforcement: capability tokens and the PEP

## The v1 gap
v1's control plane returned a status string (`"allowed"`, `"approval_required"`,
…). Nothing consumed that string. The agent could read `"approval_required"` and
execute anyway. The capability-token idea was named but unimplemented.

## The v2 model
A decision and an action are two different things. The bridge between them is a
**capability token**: a short-lived, scoped, single-use, Ed25519-signed grant.

```
agent ──signed event──▶ control plane ──decision──▶ (ALLOWED?) ──mint──▶ token
                                                                           │
agent ◀────────────────────── token ───────────────────────────────────┘
  │
  └─ wants to act ──▶ PEP.execute(token, actual_action) ──verify──▶ real tool
```

The PEP (`enforcement/pep.py`) verifies, against the **actual** action:
- signature valid and issued by the control plane;
- not expired, not revoked, not already consumed (if single-use);
- agent, workflow, and authority class match the token;
- the action's consequence rank does not exceed the token's;
- the token's structured conditions hold against the action context.

Only then does it invoke the real tool. If the decision was not ALLOWED, no token
exists, and `PEP.execute(token=None, …)` refuses. This is the structural answer
to "the control plane is advisory."

## Why the agent cannot widen its own grant
The token is minted from the same event metadata the agent signed. The agent
presents the token back with its action; the PEP independently re-verifies the
signature and checks scope. To exceed scope the agent would need the issuer's
signing key. The action context the SDK passes is derived from the signed event,
not invented at execution time.

## Deployment requirement
The PEP must be the only route to a side effect. Hold downstream credentials in
the PEP, not the agent, and isolate the network so the agent cannot reach
downstream systems directly. See THREAT_MODEL.md.


## Shared, atomic consumption across replicas (v2.2)

`single_use=True` is a once-only guarantee, and a guarantee is only as strong as
its enforcement. v2.1 held consumption and revocation in process memory, so two
API replicas sharing the same issuer keys would each accept the same single-use
token once — once-per-replica, not once. v2.2 moves that state behind a
`CapabilityStateStore`:

- **In-memory (default):** single-process, thread-safe; correct for a single
  replica or embedded use.
- **SQL (`SqlCapabilityStore`):** consume, revoke, and revoke-by-scope are
  atomic at the database and shared across every replica.

Consumption is a single conditional statement:

```sql
UPDATE capability_tokens SET consumed = 1
WHERE token_id = :id AND consumed = 0 AND revoked = 0;
```

The row lock serializes concurrent attempts; exactly one transaction matches a
row (`rowcount == 1`) and wins. There is no read-then-write window, so the
cross-replica TOCTOU race is closed. The `revoked = 0` predicate means a revoke
committing concurrently wins over a consume — revoke-versus-consume is decided
by commit order, not by which replica saw which first.

`build_control_plane_from_settings` selects the SQL backend automatically when a
database is configured. Run `CapabilityService.purge_expired()` periodically to
drop bookkeeping rows for expired tokens (safe — expired tokens are rejected
before consumption).
