# Migrating from v1 to v2

v2 is not API-compatible with v1; the data and control models changed in ways
that cannot be expressed as a patch. Treat it as a re-platform.

## Conceptual changes
- Agents now need an **Ed25519 keypair**; identity is the public key. Register
  agents with `public_key_hex`.
- Every event must be **signed**. Use the `AgentClient` SDK (`build_event` signs
  for you) or sign `event.signing_payload()` directly.
- Decisions are **idempotent per event**; submit one terminal decision per event.
  Re-running an approval against the same event raises an error.
- Default autonomy is **Observe-Only**. Re-earn autonomy under the new,
  stricter (Wilson-lower-bound) thresholds; v1 trust counts do not carry over
  because they conflated clean and modified approvals and allowed replays.
- Execution must go through the **PEP**. An integration that called a tool
  directly after reading a status string must be rewritten to present the
  capability token to `PEP.execute`.

## Mechanical steps
1. Provision keypairs; re-register agents with public keys.
2. Replace direct tool calls with `AgentClient.execute(...)`.
3. Move any v1 boundary config into code-level boundary rules or the policy YAML
   (policy may only tighten).
4. Stand up OIDC, key custody, and ledger anchoring (see PRODUCTION_DEPLOYMENT).
5. Run in shadow mode and let autonomy re-accrue.
