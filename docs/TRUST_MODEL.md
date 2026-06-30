# Trust model

## Earning autonomy
Trust is tracked per `(agent, workflow, authority_class)`. An agent earns
autonomy by accumulating **clean, human-approved, distinct** decisions.

## Why the Wilson lower bound
v1 used the raw approval rate as both the signal and the "confidence" — circular,
and wildly optimistic at small sample sizes (3/3 = 100%). v2 uses the **Wilson
score lower bound** on the clean-approval rate. It builds in a penalty for thin
evidence automatically:

| clean / total | point estimate | Wilson lower bound (95%) |
|---------------|----------------|--------------------------|
| 5 / 5         | 1.000          | ~0.566                   |
| 20 / 20       | 1.000          | ~0.839                   |
| 30 / 30       | 1.000          | ~0.886                   |
| 40 / 40       | 1.000          | ~0.912                   |

So Conditional Autonomy (lower bound ≥ 0.88) needs ~30 clean decisions, not the
flat 25 button-presses v1 accepted. The bound *is* the confidence number we
report — no circularity.

## Clean vs modified
A `MODIFIED_AND_APPROVED` outcome means a human had to fix the agent's work. That
is a partial failure. It is tracked separately and does **not** raise the clean
lower bound. An agent that is always "approved with edits" never earns autonomy.

## Severity-coupled sample sizes
Minimum sample size scales with the authority class's base risk
(`SAMPLES_BY_RISK`). Low-risk classes can relax after tens of decisions; HIGH and
CRITICAL classes require effectively unbounded evidence and are additionally
capped by the ceiling, so they never auto-relax.

## Ceilings beat trust
`MAX_AUTONOMY_BY_RISK` caps every authority class. No history, recommendation, or
delegation rule can exceed it. The recommendation engine, the rule-approval path,
and the policy engine all clamp to the ceiling independently (defense in depth).

## Gaming resistance
- Distinct-event counting + nonces: replaying one approval does not count twice.
- Modified ≠ clean: you cannot grind autonomy on sloppy, human-corrected work.
- Per-class tracking: success on easy authority classes does not transfer to
  risky ones; each class earns independently and is capped independently.
