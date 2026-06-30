# Roadmap

Honest list of what would harden this further, roughly in priority order.

1. **YAML policy loader** wired into `PolicyEngine` (the schema exists in
   `policies/`; the adapter is intentionally thin and not yet the source of
   truth — code invariants are).
2. **Reference anchor sinks** (RFC 9162 transparency log; S3 Object Lock) as
   drop-in `anchor_sink` implementations.
3. **Admin/approver UI** over the API (queue, autonomy map, audit viewer).
4. **Anomaly detector** feeding the `anomaly` signal that levels 6/7 react to
   (currently supplied via event metadata by the integrator).
5. **Key rotation + per-agent key lifecycle** management.
6. **Alembic migrations** instead of create-all for the SQL store.
7. **Independent security review and load testing** before any
   irreversible-class delegation is considered (it is ceiling-blocked today).
