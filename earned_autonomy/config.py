from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass
class Settings:
    """Runtime configuration, sourced from environment variables.

    In production these come from a secrets manager / orchestrator env, not a
    committed file. `.env.example` documents the full set.
    """
    strict_mode: bool = True
    database_url: str = "memory"  # "memory" | "sqlite:///eal.db" | "postgresql+psycopg://..."
    ledger_path: str | None = None
    issuer_private_key_hex: str | None = None
    issuer_public_key_hex: str | None = None
    capability_ttl_seconds: int = 300
    oidc_issuer: str | None = None
    oidc_audience: str | None = None
    oidc_jwks_url: str | None = None
    dev_auth_secret: str | None = None  # HMAC fallback for local dev only
    log_level: str = "INFO"

    @classmethod
    def from_env(cls) -> "Settings":
        def _bool(name: str, default: bool) -> bool:
            v = os.getenv(name)
            return default if v is None else v.lower() in ("1", "true", "yes", "on")

        return cls(
            strict_mode=_bool("EAL_STRICT_MODE", True),
            database_url=os.getenv("EAL_DATABASE_URL", "memory"),
            ledger_path=os.getenv("EAL_LEDGER_PATH"),
            issuer_private_key_hex=os.getenv("EAL_ISSUER_PRIVATE_KEY_HEX"),
            issuer_public_key_hex=os.getenv("EAL_ISSUER_PUBLIC_KEY_HEX"),
            capability_ttl_seconds=int(os.getenv("EAL_CAPABILITY_TTL_SECONDS", "300")),
            oidc_issuer=os.getenv("EAL_OIDC_ISSUER"),
            oidc_audience=os.getenv("EAL_OIDC_AUDIENCE"),
            oidc_jwks_url=os.getenv("EAL_OIDC_JWKS_URL"),
            dev_auth_secret=os.getenv("EAL_DEV_AUTH_SECRET"),
            log_level=os.getenv("EAL_LOG_LEVEL", "INFO"),
        )
