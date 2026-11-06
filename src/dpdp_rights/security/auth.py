"""Authentication and role-based authorization for the Rights API.

Two methods, usable together:

* API keys   - for backend services. Only the SHA-256 of each key is kept in config.
* OIDC JWTs  - for people (DPOs, approvers) and self-service Data Principals, from any OIDC
               issuer: Amazon Cognito, Google Identity Platform, Entra ID, Okta, Auth0, Keycloak.

Roles:
  principal - a Data Principal acting on their own data (JWT subject = external_id)
  service   - an application backend (record consent, submit requests on a principal's behalf)
  dpo       - Data Protection Officer: all requests, lineage, certificates, attested verification,
              break-glass requests
  approver  - second person who approves break-glass access
  admin     - everything
"""
from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field

from ..core.config import AuthConfig

ROLES = {"principal", "service", "dpo", "approver", "reviewer", "admin"}


class AuthError(Exception):
    def __init__(self, status: int, detail: str):
        super().__init__(detail)
        self.status, self.detail = status, detail


@dataclass(frozen=True)
class Caller:
    name: str
    kind: str                                  # api_key | oidc | anonymous
    roles: frozenset[str] = field(default_factory=frozenset)
    tenant: str | None = None
    subject: str | None = None                 # external_id for self-service principals

    def has(self, *roles: str) -> bool:
        return "admin" in self.roles or bool(self.roles & set(roles))

    @property
    def label(self) -> str:
        return f"{self.kind}:{self.name}"


def hash_api_key(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


class Authenticator:
    def __init__(self, cfg: AuthConfig, environment: str = "dev", jwk_client=None):
        self.cfg, self.environment = cfg, environment
        self._jwk = jwk_client
        if cfg.mode in ("oidc", "both") and cfg.oidc is None:
            raise ValueError("api.auth.oidc must be configured for mode oidc/both")

    def _jwk_client(self):
        if self._jwk is None:
            import jwt

            url = self.cfg.oidc.jwks_url or self.cfg.oidc.issuer.rstrip("/") + "/.well-known/jwks.json"
            self._jwk = jwt.PyJWKClient(url, cache_keys=True)
        return self._jwk

    def authenticate(self, headers: dict[str, str]) -> Caller:
        h = {k.lower(): v for k, v in headers.items()}
        mode = self.cfg.mode
        if mode == "none":
            if self.environment == "production":
                raise AuthError(500, "authentication disabled in production")
            # Development only (refused above in production). X-Dev-User names the local caller, so a local
            # walkthrough can show separation of duties: one person submits, another decides.
            name = (h.get("x-dev-user") or "dev").strip()[:64] or "dev"
            return Caller(name, "anonymous", frozenset({"admin"}))

        authz = h.get("authorization", "")
        if mode in ("api_key", "both"):
            raw = h.get("x-api-key") or (authz[7:] if authz.lower().startswith("apikey ") else None)
            if raw:
                digest = hash_api_key(raw)
                for k in self.cfg.api_keys:
                    if hmac.compare_digest(digest, k.sha256.lower()):
                        return Caller(k.name, "api_key", frozenset(k.roles), k.tenant)
                raise AuthError(401, "invalid API key")

        if mode in ("oidc", "both") and authz.lower().startswith("bearer "):
            return self._verify_jwt(authz[7:])
        raise AuthError(401, "missing credentials")

    def _verify_jwt(self, token: str) -> Caller:
        import jwt

        o = self.cfg.oidc
        try:
            key = self._jwk_client().get_signing_key_from_jwt(token).key
            claims = jwt.decode(token, key, algorithms=o.algorithms, audience=o.audience, issuer=o.issuer,
                                options={"require": ["exp", "iat", "sub"]})
        except Exception as e:  # noqa: BLE001
            raise AuthError(401, f"invalid token: {e}") from e
        roles = claims.get(o.roles_claim) or []
        if isinstance(roles, str):
            roles = roles.replace(",", " ").split()
        roles = {r for r in roles if r in ROLES} or {"principal"}
        sub = str(claims.get(o.subject_claim))
        return Caller(claims.get("email") or sub, "oidc", frozenset(roles), claims.get(o.tenant_claim),
                      subject=sub if "principal" in roles else None)
