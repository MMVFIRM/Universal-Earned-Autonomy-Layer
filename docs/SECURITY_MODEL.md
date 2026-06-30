# Security model (summary)

- **Identity**: Ed25519 keys. Agents sign events; the issuer signs tokens and
  ledger records. Keys are supplied to the process; custody (HSM/KMS) is a
  deployment responsibility.
- **Authorization**: capability tokens scope a single action; the PEP enforces.
- **Human auth**: OIDC/JWT with RBAC; dev HMAC fallback refused in strict mode
  without an issuer.
- **Audit**: signed, chained, checkpointed, externally anchorable.
- **Fail-closed**: unknown guards count as fired; malformed tokens/signatures
  verify to false; strict mode is the default.

See THREAT_MODEL.md for the boundary between what the code guarantees and what
deployment must provide.
