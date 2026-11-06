"""Audited break-glass access to sealed data (legal hold and statutory retention escrow).

Sealed data is unreadable by applications. Reading it (for example to answer a regulator or
a court order) requires:

1. a grant requested by a DPO, with a reason and a ticket reference
2. approval by a *different* person (two-person rule), unless disabled
3. reads within the grant's time window, by the requester only

Every attempt, allowed or denied, is written to ``access_log``. In production, also configure
``vault.sealed_key_wrapper`` with a KMS key that only a break-glass IAM role can decrypt, so the
control is enforced by the cloud provider and not only by this code.
"""
from __future__ import annotations

from datetime import timedelta

from sqlalchemy import select, update

from ..core.config import BreakGlassConfig
from ..core.models import new_id, utcnow
from ..lineage.store import LineageStore, access_grant, access_log
from ..vault.vault import Vault


class AccessDenied(PermissionError):
    pass


class BreakGlass:
    def __init__(self, store: LineageStore, vault: Vault, cfg: BreakGlassConfig):
        self.store, self.vault, self.cfg = store, vault, cfg

    def _log(self, grant_id, actor, outcome, token=None, detail=None):
        with self.store.engine.begin() as c:
            c.execute(access_log.insert().values(log_id=new_id("acl"), grant_id=grant_id, actor=actor,
                                                 token=token, outcome=outcome, detail=detail, at=utcnow()))

    def _grant(self, grant_id: str) -> dict:
        with self.store.engine.connect() as c:
            r = c.execute(select(access_grant).where(access_grant.c.grant_id == grant_id)).first()
        if not r:
            raise AccessDenied("unknown grant")
        return dict(r._mapping)

    def request(self, principal_id: str, requested_by: str, reason: str, ticket_ref: str) -> dict:
        if not reason.strip() or not ticket_ref.strip():
            raise ValueError("reason and ticket_ref are required")
        gid = new_id("bg")
        auto = not self.cfg.require_second_approver
        expires = utcnow() + timedelta(minutes=self.cfg.max_grant_minutes) if auto else None
        with self.store.engine.begin() as c:
            c.execute(access_grant.insert().values(
                grant_id=gid, sealed_id=principal_id, requested_by=requested_by, reason=reason,
                ticket_ref=ticket_ref, status="active" if auto else "pending", created_at=utcnow(),
                expires_at=expires, approved_by="auto" if auto else None))
        self._log(gid, requested_by, "requested", detail=reason)
        return self._grant(gid)

    def approve(self, grant_id: str, approver: str) -> dict:
        g = self._grant(grant_id)
        if g["status"] != "pending":
            raise AccessDenied(f"grant is {g['status']}")
        if approver == g["requested_by"]:
            self._log(grant_id, approver, "denied", detail="self-approval")
            raise AccessDenied("approver must be a different person from the requester")
        with self.store.engine.begin() as c:
            c.execute(update(access_grant).where(access_grant.c.grant_id == grant_id).values(
                status="active", approved_by=approver,
                expires_at=utcnow() + timedelta(minutes=self.cfg.max_grant_minutes)))
        self._log(grant_id, approver, "approved")
        return self._grant(grant_id)

    def revoke(self, grant_id: str, actor: str) -> None:
        with self.store.engine.begin() as c:
            c.execute(update(access_grant).where(access_grant.c.grant_id == grant_id).values(status="revoked"))
        self._log(grant_id, actor, "revoked")

    def read(self, grant_id: str, actor: str, tokens: list[str]) -> dict[str, str | None]:
        g = self._grant(grant_id)
        exp = g["expires_at"]
        if exp is not None and exp.tzinfo is None:
            exp = exp.replace(tzinfo=utcnow().tzinfo)
        if g["status"] != "active" or exp is None or exp < utcnow():
            self._log(grant_id, actor, "denied", detail=f"grant {g['status']}")
            raise AccessDenied("grant is not active")
        if actor != g["requested_by"]:
            self._log(grant_id, actor, "denied", detail="not the requester")
            raise AccessDenied("only the requester may use this grant")
        sealed = {f"hold_{g['sealed_id']}", f"escrow_{g['sealed_id']}"}
        out: dict[str, str | None] = {}
        for t in tokens:
            if self.vault.owner_of(t) not in sealed:
                self._log(grant_id, actor, "denied", token=t, detail="token outside grant scope")
                out[t] = None
                continue
            out[t] = self.vault.detokenize(t, privileged=True)
            self._log(grant_id, actor, "allowed", token=t)
        return out

    def audit(self, grant_id: str | None = None) -> list[dict]:
        q = select(access_log).order_by(access_log.c.at)
        if grant_id:
            q = q.where(access_log.c.grant_id == grant_id)
        with self.store.engine.connect() as c:
            return [dict(r._mapping) for r in c.execute(q)]
