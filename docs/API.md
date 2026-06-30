# HTTP API

Requires the `[api]` extra. Auth: `Authorization: Bearer <jwt>`; mutating routes
require a role (RBAC). Agent events are additionally authenticated by the
Ed25519 signature inside the event.

| Method | Path | Role | Purpose |
|--------|------|------|---------|
| GET  | `/healthz` | — | liveness |
| GET  | `/metrics` | — | Prometheus governance metrics (internal port) |
| GET  | `/audit/verify` | auditor | verify the signed ledger |
| POST | `/agents` | agent_admin | register an agent (with public key) |
| POST | `/events` | agent_gateway | propose a signed workflow event |
| POST | `/decisions` | approver | submit an approval decision |
| POST | `/delegation-rules` | autonomy_admin | enact a delegation rule |
| POST | `/incidents` | autonomy_admin | record an incident (auto-revokes rules) |
| GET  | `/agents/{id}/autonomy-map` | auditor | current autonomy + active rules |

Responses mirror the in-process objects (`*.to_dict()`). `POST /events` returns
the policy decision and, when allowed, a capability token to present to the PEP.

Errors: 401 (auth), 403 (role), 409 (separation-of-duties / ceiling violation),
400 (replay / bad request).

Every response carries an `x-request-id` header (echoed from the request or generated) for correlation with structured logs and the audit ledger.
