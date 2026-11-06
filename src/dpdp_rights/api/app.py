"""Rights API (FastAPI): consent, withdrawal, erasure, certificates, break-glass.

    dpdp-rights -c config/dpdp.local.yaml serve
    uvicorn dpdp_rights.api.app:default_app --factory     (reads DPDP_CONFIG)

Every endpoint except /healthz is authenticated (API key or OIDC JWT) and role-checked. The
tenant comes from the credential, never from the request body. Erasure and withdrawal requests
are verified (OTP, authenticated session or DPO attestation) and then processed by workers from
a durable queue (`dpdp-rights worker`).
"""
from __future__ import annotations

import json
import os

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from pydantic import BaseModel

from ..consent.ledger import ConsentDenied
from ..core.config import FrameworkConfig
from ..framework import DataRightsFramework
from ..security.auth import Authenticator, AuthError, Caller
from ..security.breakglass import AccessDenied
from ..security.tenancy import TenantRegistry
from ..security.verification import VerificationError


class ConsentIn(BaseModel):
    external_id: str
    purpose_id: str
    element_types: list[str] | None = None
    notice_version: str = "v1"
    consent_manager_ref: str | None = None


class RequestIn(BaseModel):
    external_id: str
    scope: str = "full"
    evidence: str | None = None          # DPO attestation reference (e.g. video-KYC ticket)
    dry_run: bool = False


class WithdrawIn(BaseModel):
    external_id: str
    purpose_id: str
    evidence: str | None = None


class CodeIn(BaseModel):
    code: str


class GrantIn(BaseModel):
    principal_id: str
    reason: str
    ticket_ref: str


class ReadIn(BaseModel):
    tokens: list[str]


def create_app(dpdp: DataRightsFramework | None = None, config: FrameworkConfig | None = None,
               authenticator: Authenticator | None = None) -> FastAPI:
    cfg = config or dpdp.config
    registry = TenantRegistry(cfg, lambda c: dpdp if (dpdp is not None and c is cfg) else DataRightsFramework(c))
    auth = authenticator or Authenticator(cfg.api.auth, cfg.environment)
    app = FastAPI(title="DPDP Data Rights Framework", version="0.2.0")

    def caller(request: Request) -> Caller:
        try:
            return auth.authenticate(dict(request.headers))
        except AuthError as e:
            raise HTTPException(e.status, e.detail) from e

    def need(c: Caller, *roles: str) -> None:
        if not c.has(*roles):
            raise HTTPException(403, f"requires role: {' or '.join(roles)}")

    def fw(c: Caller) -> DataRightsFramework:
        try:
            return registry.for_caller(c)
        except AuthError as e:
            raise HTTPException(e.status, e.detail) from e

    def resolve(f: DataRightsFramework, external_id: str) -> str:
        pid = f.vault.resolve_principal(external_id, create=False)
        if not pid:
            raise HTTPException(404, "unknown data principal")
        return pid

    def verification_for(c: Caller, external_id: str, evidence: str | None) -> str:
        if "principal" in c.roles and not c.has("dpo", "service"):
            if c.subject != external_id:
                raise HTTPException(403, "principals may only act on their own data")
            return "authenticated_session"
        if c.has("dpo") and evidence:
            return "dpo_attested"
        return "otp"

    def own_or_dpo(c: Caller, f: DataRightsFramework, request_id: str) -> dict:
        r = f.store.get_request(request_id)
        if not r:
            raise HTTPException(404)
        if c.has("dpo", "service"):
            return r
        if "principal" in c.roles and c.subject and f.vault.resolve_principal(c.subject, create=False) == r["principal_id"]:
            return r
        raise HTTPException(403)

    def submit(c, f, pid, **kw):
        try:
            return f.submit_request(pid, requested_by=c.label, **kw)
        except VerificationError as e:
            raise HTTPException(422, str(e)) from e

    @app.get("/healthz")
    def health():
        return {"ok": True}

    @app.post("/v1/consents")
    def grant(body: ConsentIn, c: Caller = Depends(caller)):
        need(c, "service", "dpo")
        f = fw(c)
        pid = f.principal(body.external_id)
        ids = f.grant_consent(pid, body.purpose_id, body.element_types, notice_version=body.notice_version,
                              consent_manager_ref=body.consent_manager_ref)
        return {"principal_id": pid, "consent_ids": ids}

    @app.post("/v1/withdrawals", status_code=202)
    def withdraw(body: WithdrawIn, c: Caller = Depends(caller),
                 idempotency_key: str | None = Header(default=None)):
        need(c, "principal", "service", "dpo")
        f = fw(c)
        method = verification_for(c, body.external_id, body.evidence)
        return submit(c, f, resolve(f, body.external_id), withdraw_purpose=body.purpose_id, verification=method,
                      evidence=body.evidence, idempotency_key=idempotency_key)

    @app.post("/v1/erasure-requests", status_code=202)
    def erasure(body: RequestIn, c: Caller = Depends(caller),
                idempotency_key: str | None = Header(default=None)):
        need(c, "principal", "service", "dpo")
        f = fw(c)
        if body.dry_run:
            need(c, "dpo")
            pid = resolve(f, body.external_id)
            return f.erase(pid, scope=body.scope, dry_run=True, requested_via="api-dry-run")
        method = verification_for(c, body.external_id, body.evidence)
        return submit(c, f, resolve(f, body.external_id), scope=body.scope, verification=method,
                      evidence=body.evidence, idempotency_key=idempotency_key)

    @app.post("/v1/erasure-requests/{request_id}/verify")
    def verify(request_id: str, body: CodeIn, c: Caller = Depends(caller)):
        need(c, "principal", "service", "dpo")
        f = fw(c)
        own_or_dpo(c, f, request_id)
        try:
            return f.confirm_request(request_id, body.code)
        except VerificationError as e:
            raise HTTPException(422, str(e)) from e

    @app.get("/v1/erasure-requests/{request_id}")
    def status(request_id: str, c: Caller = Depends(caller)):
        f = fw(c)
        r = own_or_dpo(c, f, request_id)
        out = {"request": {k: r[k] for k in ("request_id", "scope", "status", "received_at", "due_by",
                                             "completed_at", "verification_method")}}
        if c.has("dpo"):
            out["actions"] = f.store.actions_for(request_id)
        return out

    @app.get("/v1/erasure-requests/{request_id}/certificate")
    def certificate(request_id: str, c: Caller = Depends(caller)):
        f = fw(c)
        own_or_dpo(c, f, request_id)
        cert = f.store.get_certificate(request_id)
        if not cert:
            raise HTTPException(404, "no certificate yet")
        return {"sha256": cert["sha256"], "prev_sha256": cert["prev_sha256"], "signature": cert["signature"],
                "signer": cert["signer"], "archive_uri": cert["archive_uri"], "payload": json.loads(cert["payload"])}

    @app.get("/v1/erasure-requests/{request_id}/certificate/verify")
    def certificate_verify(request_id: str, c: Caller = Depends(caller)):
        need(c, "dpo")
        try:
            return fw(c).verify_certificate(request_id)
        except KeyError as e:
            raise HTTPException(404, str(e)) from e

    @app.get("/v1/principals/{principal_id}/lineage")
    def lineage(principal_id: str, c: Caller = Depends(caller)):
        need(c, "dpo")
        return fw(c).lineage(principal_id)

    @app.get("/v1/sla")
    def sla(c: Caller = Depends(caller)):
        need(c, "dpo")
        f = fw(c)
        return {"open_requests": f.sla_counts(), "jobs": f.queue.counts()}

    # ---- break-glass ------------------------------------------------------
    @app.post("/v1/break-glass/grants")
    def bg_request(body: GrantIn, c: Caller = Depends(caller)):
        need(c, "dpo")
        try:
            return fw(c).break_glass.request(body.principal_id, c.label, body.reason, body.ticket_ref)
        except ValueError as e:
            raise HTTPException(422, str(e)) from e

    @app.post("/v1/break-glass/grants/{grant_id}/approve")
    def bg_approve(grant_id: str, c: Caller = Depends(caller)):
        need(c, "approver")
        try:
            return fw(c).break_glass.approve(grant_id, c.label)
        except AccessDenied as e:
            raise HTTPException(403, str(e)) from e

    @app.post("/v1/break-glass/grants/{grant_id}/revoke")
    def bg_revoke(grant_id: str, c: Caller = Depends(caller)):
        need(c, "dpo", "approver")
        fw(c).break_glass.revoke(grant_id, c.label)
        return {"revoked": grant_id}

    @app.post("/v1/break-glass/grants/{grant_id}/read")
    def bg_read(grant_id: str, body: ReadIn, c: Caller = Depends(caller)):
        need(c, "dpo")
        try:
            return {"values": fw(c).break_glass.read(grant_id, c.label, body.tokens)}
        except AccessDenied as e:
            raise HTTPException(403, str(e)) from e

    @app.get("/v1/break-glass/audit")
    def bg_audit(grant_id: str | None = None, c: Caller = Depends(caller)):
        need(c, "dpo", "approver")
        return fw(c).break_glass.audit(grant_id)

    @app.exception_handler(ConsentDenied)
    def _consent(_req, exc):
        from fastapi.responses import JSONResponse

        return JSONResponse({"detail": str(exc)}, status_code=403)

    return app


def default_app() -> FastAPI:
    return create_app(config=FrameworkConfig.load(os.environ.get("DPDP_CONFIG", "config/dpdp.local.yaml")))
