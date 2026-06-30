# Threat Model

## What this layer defends

The control plane sits between an AI agent and the systems it can affect. Its job
is to ensure that an agent only causes a side effect it has been *authorized* to
cause, that authorization is *earned* and *revocable*, and that everything is
*attributable* after the fact.

### Assets
- Downstream systems the agent can mutate (CRM, email, payments, infra).
- The autonomy state (who may do what, at what level).
- The audit trail.

### Trust boundaries
1. **Agent ↔ control plane.** The agent is *not* trusted. It authenticates each
   event with an Ed25519 signature; identity is its public key. The control
   plane never accepts a self-asserted identity or an unsigned event in strict
   mode.
2. **Control plane ↔ enforcement point.** The decision is bound to the action by
   a signed capability token. The PEP is the only path to a side effect and
   re-verifies the token against the actual action.
3. **Human approver ↔ control plane.** Humans authenticate via OIDC. Separation
   of duties prevents an agent's owner from rubber-stamping their own agent for
   consequential classes.

## Attacker capabilities considered

| Attacker | Capability | Mitigation |
|----------|-----------|------------|
| Compromised/malicious agent | Forge identity | Signature verification; unknown agents rejected |
| | Replay a past approved event | Atomic per-agent nonce claim (unique constraint, shared across replicas); idempotent decisions |
| | Use a grant for a different action | PEP checks actual action vs token scope |
| | Game trust with easy/repeated events | Distinct-event counting; Wilson LB; severity-coupled samples |
| | Proceed after a blocked decision | No token issued → PEP refuses |
| Insider (agent owner) | Approve own agent into autonomy | Separation of duties on consequential classes |
| Tamperer with ledger write access | Edit a record | Hash chain + per-record signature |
| Tamperer with the ledger key | Rewrite history | External checkpoint anchoring (deployment-provided) |

## Explicitly out of scope (deployment must address)
- **Key custody.** If issuer/agent private keys are mishandled, the guarantees
  collapse. Use an HSM/KMS. This repo operates on key material; it does not store
  it.
- **PEP bypass.** If an agent has a direct network path to a downstream system
  that does not pass through the PEP, the layer cannot help. The PEP must be the
  sole egress for side effects (network policy / broker credentials held only by
  the PEP).
- **IdP compromise.** Human auth is delegated to OIDC; a compromised IdP is out
  of scope here.
- **Classifier evasion.** The lexical classifier is advisory and can only raise
  risk. Binding constraints come from the authority ontology and ceilings, so
  classifier evasion cannot *lower* risk — but do not treat the classifier as a
  security control.
- **Model-level attacks** (prompt injection of the agent itself). This layer
  constrains the *blast radius* of a subverted agent; it does not prevent
  subversion.

## A note on the v1 anti-pattern
The recurring v1 failure was a trust boundary that *moved up a level but was
implemented one notch weaker than required* — e.g., an incident lowered the
agent's level but left the delegation rule that overrode that level intact. v2's
design rule: when a boundary tightens, every path that could grant the old
authority must tighten with it. The incident handler revoking matching rules
(not just lowering the level) is the canonical example, and it has a dedicated
regression test.
