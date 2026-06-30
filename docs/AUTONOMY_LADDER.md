# The autonomy ladder

Eight rungs per `(workflow, authority_class)`. Each rung has distinct runtime
behavior — v1's levels 5/6/7 collapsed to the same outcome; v2's do not.

| Lvl | Name | Runtime behavior |
|-----|------|------------------|
| 0 | Observe Only | Only non-state/informational actions allowed; any state change → approval. Default for every new agent. |
| 1 | Suggest | + internal non-state cognition (score, classify, recommend) allowed. |
| 2 | Draft | + drafting work product allowed; still no execution. |
| 3 | Execute With Approval | State changes allowed only after human approval. |
| 4 | Execute With Sampling | State changes execute; a sampled fraction is routed for human review (`SAMPLE_REVIEW`). |
| 5 | Conditional Autonomy | Executes within the policy envelope; rule conditions + guards enforced. |
| 6 | Exception-Based Supervision | Executes unless an anomaly/exception signal is present, in which case it ESCALATES. |
| 7 | Delegated Authority | Broadest autonomy within the envelope, with periodic attestation (a baseline sample rate) and anomaly escalation. |

## Distinct semantics, concretely
- Level **5** ignores an `anomaly` flag and proceeds (the envelope is the
  control).
- Level **6** ESCALATES when `anomaly` is set; otherwise proceeds with no
  sampling.
- Level **7** proceeds like 6 but always carries a non-zero sample rate
  (periodic attestation), so even fully delegated authority is continuously
  spot-checked.

## Ceilings
A rung is only reachable if it is at or below the authority class's risk ceiling
(`MAX_AUTONOMY_BY_RISK`). For example `transfer_value` and `delete_data` top out
at level 3 — they can never reach 4–7, regardless of trust.
