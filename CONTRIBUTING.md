# Contributing

1. `make dev` to install with all extras.
2. `make test` and `make lint` must pass.
3. Any change touching the safety surface (policy, ceilings, capability tokens,
   ledger, auth) MUST include or update a test in `tests/`, and changes that
   affect a v1 regression must keep `tests/test_regression_v1_bugs.py` green.
4. Safety invariants live in code, not YAML. Policy files may only make behavior
   more restrictive; do not move an invariant into configuration where it can be
   weakened silently.
