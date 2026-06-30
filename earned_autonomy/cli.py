"""Command-line interface for the Earned Autonomy Layer.

Usage:
  python -m earned_autonomy.cli keygen
  python -m earned_autonomy.cli demo
  python -m earned_autonomy.cli sales-demo
  python -m earned_autonomy.cli serve            # requires [api] extra
"""
from __future__ import annotations

import argparse
import sys

from .crypto import generate_keypair


def cmd_keygen(_args) -> int:
    kp = generate_keypair()
    print("# Ed25519 keypair. Keep the private key in a secrets manager.")
    print(f"EAL_ISSUER_PRIVATE_KEY_HEX={kp.private_key_hex}")
    print(f"EAL_ISSUER_PUBLIC_KEY_HEX={kp.public_key_hex}")
    return 0


def cmd_demo(_args) -> int:
    from earned_autonomy.examples.agent_sdk_demo import main as run
    run()
    return 0


def cmd_sales_demo(_args) -> int:
    from earned_autonomy.examples.sales_rep_demo import main as run
    run()
    return 0


def cmd_initdb(_args) -> int:
    from .config import Settings
    settings = Settings.from_env()
    url = settings.database_url
    if not url or url == "memory":
        print("EAL_DATABASE_URL is 'memory'; nothing to initialize. Set a real DB URL.", file=sys.stderr)
        return 1
    from .core.capability_store import SqlCapabilityStore
    from .core.ledger_sql import SqlAuditLedger
    from .storage.sql import SqlStore
    if SqlStore is None or SqlCapabilityStore is None or SqlAuditLedger is None:
        print("SQL extras not installed: pip install -e '.[sql]'", file=sys.stderr)
        return 1
    # Constructing each store runs create_all / metadata.create_all for its tables.
    SqlStore(url)
    SqlCapabilityStore(url)
    key = settings.issuer_private_key_hex or "00" * 32
    SqlAuditLedger(key, settings.issuer_public_key_hex or "00" * 32, url)
    print(f"Initialized schema at {url}")
    print("Tables: agents, events, delegation_rules, agent_nonces, capability_tokens, audit_ledger")
    print("For production, wrap these DDL operations in Alembic migrations (see docs/PRODUCTION_DEPLOYMENT.md).")
    return 0


def cmd_serve(args) -> int:
    try:
        import uvicorn
    except ImportError:
        print("The [api] extra is required: pip install -e '.[api]'", file=sys.stderr)
        return 1
    uvicorn.run("earned_autonomy.api.server:create_app", factory=True, host=args.host, port=args.port)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="eal", description="Universal Earned Autonomy Layer")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("keygen", help="Generate an Ed25519 issuer keypair").set_defaults(func=cmd_keygen)
    sub.add_parser("demo", help="Run the end-to-end SDK lifecycle demo").set_defaults(func=cmd_demo)
    sub.add_parser("sales-demo", help="Run the guardrail scenario demo").set_defaults(func=cmd_sales_demo)
    sub.add_parser("init-db", help="Create all SQL tables for EAL_DATABASE_URL").set_defaults(func=cmd_initdb)
    serve = sub.add_parser("serve", help="Run the HTTP API (requires [api] extra)")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    serve.set_defaults(func=cmd_serve)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
