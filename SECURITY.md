# Security Policy

## Reporting
Report vulnerabilities privately to security@mmv.example (placeholder). Do not
open public issues for security reports.

## Security properties this layer is designed to provide
- **Agent authentication**: every workflow event is Ed25519-signed; identity is
  a public key, not a self-asserted string. Unsigned/forged events are rejected
  in strict mode.
- **Enforcement, not advice**: state-changing actions execute only through a
  Policy Enforcement Point that verifies a capability token against the actual
  action. A blocked/approval decision issues no token.
- **Replay resistance**: per-agent event nonces and idempotent, one-per-event
  decisions prevent replay-based trust inflation.
- **Risk ceilings**: high-risk/irreversible authority classes cannot reach
  autonomous execution regardless of trust history.
- **Tamper-evident audit**: hash-chained, Ed25519-signed records with periodic
  signed checkpoints and an external-anchor hook.

## Properties that depend on correct deployment (see docs/THREAT_MODEL.md)
- Private key custody (HSM/KMS) for issuer and agent keys.
- A real OIDC IdP for human/admin authentication.
- External anchoring of ledger checkpoints to immutable storage.
- Network isolation of the PEP from agents (the PEP must be the only path to
  downstream side effects).
