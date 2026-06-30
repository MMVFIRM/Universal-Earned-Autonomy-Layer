"""Authentication and authorization for the HTTP control plane.

Two principal types authenticate differently:
  * Humans / services calling the admin + approval API authenticate with an
    OIDC-issued JWT (verified against the IdP's JWKS). For local development a
    symmetric HMAC token signed with EAL_DEV_AUTH_SECRET is accepted instead;
    this fallback is refused when strict_mode is on AND no OIDC issuer is set,
    so production cannot silently run on dev auth.
  * Agents authenticate per-event with Ed25519 signatures (handled in the
    control plane), NOT with these bearer tokens.

RBAC is role-based: endpoints declare a required role; a principal's roles come
from the verified token claims. This module deliberately does not invent its own
user store — identity is delegated to the IdP.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

from ..config import Settings


class AuthError(Exception):
    pass


@dataclass
class Principal:
    subject: str
    roles: List[str]
    method: str  # "oidc" | "dev-hmac"


class Authenticator:
    def __init__(self, settings: Settings):
        self.settings = settings

    def authenticate(self, bearer_token: Optional[str]) -> Principal:
        if not bearer_token:
            raise AuthError("missing bearer token")
        token = bearer_token.removeprefix("Bearer ").strip()

        if self.settings.oidc_issuer and self.settings.oidc_jwks_url:
            return self._verify_oidc(token)

        # Dev fallback. It is deliberately disabled in strict mode. Production
        # must use OIDC/JWKS; otherwise a committed or weak HMAC secret becomes
        # the whole admin boundary.
        if self.settings.strict_mode:
            raise AuthError("no OIDC configured; dev auth is disabled in strict mode")
        if not self.settings.dev_auth_secret:
            raise AuthError("no auth configured")
        return self._verify_dev_hmac(token)

    def _verify_oidc(self, token: str) -> Principal:
        try:
            import jwt
            from jwt import PyJWKClient
        except ImportError as exc:  # pragma: no cover - optional dep
            raise AuthError("pyjwt not installed; install '.[api]'") from exc

        jwk_client = PyJWKClient(self.settings.oidc_jwks_url)
        signing_key = jwk_client.get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256", "ES256"],
            audience=self.settings.oidc_audience,
            issuer=self.settings.oidc_issuer,
        )
        roles = claims.get("roles") or claims.get("https://eal/roles") or []
        return Principal(subject=claims.get("sub", "unknown"), roles=list(roles), method="oidc")

    def _verify_dev_hmac(self, token: str) -> Principal:
        import jwt
        try:
            claims = jwt.decode(token, self.settings.dev_auth_secret, algorithms=["HS256"])
        except Exception as exc:  # pragma: no cover - error path
            raise AuthError(f"invalid dev token: {exc}") from exc
        return Principal(subject=claims.get("sub", "dev"), roles=list(claims.get("roles", [])), method="dev-hmac")


def require_role(principal: Principal, role: str) -> None:
    if role not in principal.roles and "admin" not in principal.roles:
        raise AuthError(f"principal lacks required role: {role}")
