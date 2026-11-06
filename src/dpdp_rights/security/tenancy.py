"""Tenant isolation (silo model).

Each tenant gets its own framework instance built from its own config: its own lineage database,
vault storage and KMS keys. There are no shared tables to filter, so a bug in a query cannot leak
one tenant's data to another. The API resolves the tenant from the caller's credentials (API key
``tenant`` or the OIDC ``tenant`` claim) and never from the request body.
"""
from __future__ import annotations

import threading

from ..core.config import FrameworkConfig
from .auth import AuthError, Caller


class TenantRegistry:
    def __init__(self, root: FrameworkConfig, factory):
        self.root, self.factory = root, factory      # factory(cfg) -> DataRightsFramework
        self._instances: dict[str, object] = {}
        self._lock = threading.Lock()
        if root.environment == "production" and root.tenants:
            self._check_isolation()

    @property
    def multi_tenant(self) -> bool:
        return bool(self.root.tenants)

    def _cfg(self, tenant: str) -> FrameworkConfig:
        return FrameworkConfig.load(self.root.tenants[tenant].config)

    def _check_isolation(self) -> None:
        seen_db, seen_key = {}, {}
        for t in self.root.tenants:
            c = self._cfg(t)
            for label, val, seen in (("lineage.url", c.lineage.url, seen_db), ("vault.kms_key_id", c.vault.kms_key_id, seen_key)):
                if val and val in seen:
                    raise ValueError(f"tenants '{seen[val]}' and '{t}' share {label}; each tenant needs its own")
                if val:
                    seen[val] = t

    def get(self, tenant: str | None):
        key = tenant or "__default__"
        with self._lock:
            if key not in self._instances:
                if tenant is None:
                    self._instances[key] = self.factory(self.root)
                elif tenant in self.root.tenants:
                    self._instances[key] = self.factory(self._cfg(tenant))
                else:
                    raise AuthError(403, f"unknown tenant '{tenant}'")
            return self._instances[key]

    def for_caller(self, caller: Caller):
        if self.multi_tenant:
            if not caller.tenant and "admin" not in caller.roles:
                raise AuthError(403, "credential is not bound to a tenant")
            return self.get(caller.tenant)
        return self.get(None)
