"""Rights API (FastAPI): consent, withdrawal, erasure, certificates, case records, break-glass.

    dpdp-rights -c config/dpdp.local.yaml serve
    uvicorn dpdp_rights.api.app:default_app --factory     (reads DPDP_CONFIG)

Every endpoint except /healthz is authenticated (API key or OIDC JWT) and role-checked. The
tenant comes from the credential, never from the request body. Identity verification of the Data
Principal is done upstream, in the deployer's own channel; requests arrive already verified and
carry ``verified_by`` / ``verification_ref`` for the audit trail. They are processed by workers
from a durable queue (`dpdp-rights worker`).
"""
from __future__ import annotations

import json
import os
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from pydantic import BaseModel

from ..consent.ledger import ConsentDenied
from ..core.config import FrameworkConfig
from ..framework import DataRightsFramework
from ..security.auth import Authenticator, AuthError, Caller
from ..security.breakglass import AccessDenied
from ..security.tenancy import TenantRegistry


class ConsentIn(BaseModel):
    external_id: str
    purpose_id: str
    element_types: list[str] | None = None
    notice_version: str = "v1"
    consent_manager_ref: str | None = None
    guardian_id: str | None = None       # a child or ward: the verified parent or guardian giving consent
    verification_ref: str | None = None


class DenialIn(BaseModel):
    external_id: str
    purpose_id: str
    notice_version: str | None = None


class AgeStatusIn(BaseModel):
    external_id: str
    status: str                          # adult | child | ward
    basis: str                           # how it was determined: verified, declared, fiduciary_records ...
    verification_ref: str | None = None


class GuardianIn(BaseModel):
    external_id: str                     # the child or ward
    guardian_external_id: str            # the parent or lawful guardian
    method: str                          # fiduciary_records | voluntary_details | virtual_token | court | ...
    verification_ref: str                # the check made upstream (DigiLocker transaction, KYC check, order no.)
    issuer: str | None = None            # virtual token issuer, or the appointing authority
    relationship: str | None = None      # stored as a vault token


class RevokeGuardianIn(BaseModel):
    reason: str


class RequestIn(BaseModel):
    external_id: str
    scope: str = "full"
    verified_by: str | None = None       # system or person that verified the requester upstream
    verification_ref: str | None = None  # e.g. login session id, KYC check id, case number
    dry_run: bool = False


class BreachIn(BaseModel):
    stores: list[str] = []                 # breached connector/store names
    systems: list[str] = []                # breached inventory system names
    start: str | None = None               # ISO 8601 with time zone
    end: str | None = None                 # omit if not yet known
    aware_at: str | None = None            # starts the 72-hour clock (Rules r.7(2)(b)); default now
    nature: str | None = None              # one line: what happened
    vault_compromised: bool = False
    breach_id: str | None = None           # re-assess a known breach


class WithdrawIn(BaseModel):
    external_id: str
    purpose_id: str
    verified_by: str | None = None
    verification_ref: str | None = None


class GrantIn(BaseModel):
    principal_id: str
    reason: str
    ticket_ref: str


class ReadIn(BaseModel):
    tokens: list[str]


class ManualActionIn(BaseModel):
    system: str                          # name from the deployment inventory
    action: str                          # deleted | redacted | retained | processor_instructed | ...
    reference: str                       # ticket / change / case number (no personal data)
    notes: str | None = None
    performed_at: str | None = None


class RightsIn(BaseModel):
    type: str                            # access | correction | erasure | withdrawal | nomination | nominee_invocation | grievance
    external_id: str
    verified_by: str | None = None
    verification_ref: str | None = None
    channel: str = "api"
    on_behalf_of: str | None = None      # nomination id, when a nominee acts
    details: dict[str, Any] = {}         # type-specific fields (docs/rights.md)


class DecisionIn(BaseModel):
    decision: str                        # approve | reject
    reason: str | None = None


class GrievanceResponseIn(BaseModel):
    status: str                          # acknowledged | fulfilled | rejected
    response: str | None = None


class ReviewIn(BaseModel):
    decision: str                        # approved | rejected | needs_info
    checklist: dict[str, bool | str] = {}
    notes: str | None = None


def create_app(dpdp: DataRightsFramework | None = None, config: FrameworkConfig | None = None,
               authenticator: Authenticator | None = None) -> FastAPI:
    cfg = config or dpdp.config
    registry = TenantRegistry(cfg, lambda c: dpdp if (dpdp is not None and c is cfg) else DataRightsFramework(c))
    auth = authenticator or Authenticator(cfg.api.auth, cfg.environment)
    app = FastAPI(title="DPDP Data Rights Framework", version="0.2.0", docs_url=None)
    _mount_docs(app)
    if cfg.api.console:
        _mount_console(app)

    def _authenticate(request: Request) -> Caller:
        try:
            return auth.authenticate(dict(request.headers))
        except AuthError as e:
            raise HTTPException(e.status, e.detail) from e

    if cfg.api.auth.mode == "none":
        # Development without auth: show the X-Dev-User field on every endpoint of the interactive /docs page,
        # so a local walkthrough can act as different people (one submits, another decides).
        def caller(request: Request, x_dev_user: str | None = Header(
                default=None, description="Development only: who you are acting as, e.g. app, asha, ravi. "
                                          "Ignored when authentication is on.")) -> Caller:
            return _authenticate(request)
    else:
        def caller(request: Request) -> Caller:
            return _authenticate(request)

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

    def check_self(c: Caller, external_id: str) -> None:
        if "principal" in c.roles and not c.has("dpo", "service") and c.subject != external_id:
            raise HTTPException(403, "principals may only act on their own data")

    def verified_by(c: Caller, given: str | None) -> str:
        # a principal acting through their own authenticated session is verified by that session
        if "principal" in c.roles and not c.has("dpo", "service"):
            return f"self:{c.label}"
        return given or c.label

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
        from ..core.idempotency import IdempotencyConflict

        try:
            return f.submit_request(pid, requested_by=c.label, **kw)
        except IdempotencyConflict as e:
            raise HTTPException(409, str(e)) from e
        except ValueError as e:
            raise HTTPException(422, str(e)) from e

    @app.get("/healthz")
    def health():
        return {"ok": True}

    @app.post("/v1/consents")
    def grant(body: ConsentIn, c: Caller = Depends(caller)):
        need(c, "service", "dpo")
        f = fw(c)
        pid = f.principal(body.external_id)
        try:
            ids = f.grant_consent(pid, body.purpose_id, body.element_types, notice_version=body.notice_version,
                                  consent_manager_ref=body.consent_manager_ref, guardian_id=body.guardian_id,
                                  actor=c.label, verification_ref=body.verification_ref)
        except ValueError as e:
            raise HTTPException(422, str(e)) from e
        return {"principal_id": pid, "consent_ids": ids}

    @app.post("/v1/consent-denials", status_code=201)
    def deny(body: DenialIn, c: Caller = Depends(caller)):
        need(c, "service", "dpo")
        f = fw(c)
        pid = f.principal(body.external_id)
        f.deny_consent(pid, body.purpose_id, actor=c.label, notice_version=body.notice_version)
        return {"principal_id": pid, "recorded": "denied"}

    @app.get("/v1/principals/{external_id}/consent-history")
    def consent_history(external_id: str, c: Caller = Depends(caller)):
        need(c, "principal", "dpo", "reviewer")
        check_self(c, external_id)
        f = fw(c)
        pid = resolve(f, external_id)
        return {"principal_id": pid, "events": f.consent_history.events(pid), "verify": f.consent_history.verify(pid)}

    # ---- Consent Managers (docs/consent-managers.md) ---------------------------
    # Authenticated by the Consent Manager's signature, not by an API credential. With tenants, the tenant is in the
    # query string and the signature is checked against that tenant's own Consent Manager configuration.
    @app.post("/v1/consent-managers/{name}/events")
    async def cm_events(name: str, request: Request, tenant: str | None = None):
        from ..consent.managers import CmEventError, SignatureError

        try:
            f = registry.get(tenant) if registry.multi_tenant else registry.get(None)
        except AuthError as e:
            raise HTTPException(404, "unknown consent manager") from e
        body = await request.body()
        try:
            return f.consent_managers.receive(name, dict(request.headers), body)
        except KeyError as e:
            raise HTTPException(404, "unknown consent manager") from e
        except SignatureError as e:
            raise HTTPException(401, str(e)) from e
        except CmEventError as e:
            raise HTTPException(422, str(e)) from e

    @app.get("/v1/consent-managers")
    def cm_list(c: Caller = Depends(caller)):
        need(c, "dpo", "reviewer")
        return fw(c).consent_managers.describe()

    # ---- model gateway (docs/gateway.md) --------------------------------------
    # OpenAI-compatible: point an existing app's base URL at /v1/gateway/openai/v1 and send this API's key as the
    # bearer token. The gateway calls the upstream with its own key.
    from ..gateway import GatewayRefused

    async def _gateway(route: str, path: str, request: Request):
        import os

        import httpx
        from fastapi.responses import JSONResponse, StreamingResponse

        headers = dict(request.headers)
        authz = headers.get("authorization", "")
        if authz.lower().startswith("bearer ") and authz[7:].count(".") != 2 and "x-api-key" not in headers:
            headers["x-api-key"] = authz[7:]           # OpenAI SDKs send the key as a bearer token
        try:
            c = auth.authenticate(headers)
        except AuthError as e:
            raise HTTPException(e.status, e.detail) from e
        f = fw(c)
        g = f.gateway
        if not g.cfg.enabled:
            raise HTTPException(404, "the model gateway is not enabled")
        # With subject binding, end users call with their own token (role principal) and act only for themselves.
        need(c, *(("service", "principal") if g.cfg.principal_binding == "subject" else ("service",)))
        try:
            body = await request.json()
        except ValueError as e:
            raise HTTPException(400, "body must be JSON") from e
        if not isinstance(body, dict):
            raise HTTPException(400, "body must be a JSON object")
        stream = bool(body.get("stream"))
        if stream and g.cfg.mode == "enforce" and g.cfg.reveal_responses:
            raise HTTPException(400, "streaming is not supported with reveal_responses; turn one of them off")
        try:
            out, st = g.inbound(route, body, headers, trusted={"subject": c.subject})
        except GatewayRefused as e:
            return JSONResponse({"error": {"message": str(e), "type": "dpdp_refused", "code": e.decision}},
                                status_code=e.status)
        up = {"Content-Type": "application/json"}
        key = os.environ.get(g.cfg.upstream_api_key_env or "", "")
        if key:
            up["Authorization"] = f"Bearer {key}"
        for h in ("openai-organization", "openai-project", "openai-beta"):
            if h in headers:
                up[h] = headers[h]
        url = g.cfg.upstream_base_url.rstrip("/") + path
        client = httpx.AsyncClient(timeout=g.cfg.timeout_seconds)
        if stream:
            req = client.build_request("POST", url, json=out, headers=up)
            resp = await client.send(req, stream=True)

            async def relay():
                try:
                    async for chunk in resp.aiter_bytes():      # decoded: content-encoding is not relayed
                        yield chunk
                finally:
                    await resp.aclose()
                    await client.aclose()
            return StreamingResponse(relay(), status_code=resp.status_code,
                                     media_type=resp.headers.get("content-type", "text/event-stream"))
        try:
            resp = await client.post(url, json=out, headers=up)
        except httpx.HTTPError as e:
            raise HTTPException(502, f"upstream model call failed: {type(e).__name__}") from e
        finally:
            await client.aclose()
        try:
            data = resp.json()
        except ValueError:
            return JSONResponse({"error": {"message": "upstream returned a non-JSON response"}}, status_code=502)
        if resp.status_code < 300:
            data = g.outbound(st, data)
        return JSONResponse(data, status_code=resp.status_code)

    @app.post("/v1/gateway/openai/v1/chat/completions", include_in_schema=True)
    async def gw_chat(request: Request):
        return await _gateway("chat", "/chat/completions", request)

    @app.post("/v1/gateway/openai/v1/responses")
    async def gw_responses(request: Request):
        return await _gateway("responses", "/responses", request)

    @app.post("/v1/gateway/openai/v1/embeddings")
    async def gw_embeddings(request: Request):
        return await _gateway("embeddings", "/embeddings", request)

    @app.get("/v1/gateway/report")
    def gw_report(since: str | None = None, until: str | None = None, c: Caller = Depends(caller)):
        from datetime import datetime

        need(c, "dpo", "reviewer")

        def parse(v):
            if not v:
                return None
            d = datetime.fromisoformat(v.replace("Z", "+00:00"))
            if d.tzinfo is None:
                raise HTTPException(422, "times need a time zone")
            return d
        return fw(c).gateway.report(parse(since), parse(until))

    # ---- children and wards (docs/children.md) ---------------------------------
    def children_call(fn):
        from ..consent.children import ChildrenError

        try:
            return fn()
        except KeyError as e:
            raise HTTPException(404, str(e)) from e
        except ChildrenError as e:
            raise HTTPException(422, str(e)) from e

    @app.post("/v1/children/status")
    def child_status(body: AgeStatusIn, c: Caller = Depends(caller)):
        need(c, "service", "dpo")
        f = fw(c)
        return children_call(lambda: f.children.set_status(f.principal(body.external_id), body.status,
                                                           basis=body.basis, set_by=c.label,
                                                           verification_ref=body.verification_ref))

    @app.post("/v1/children/guardians", status_code=201)
    def child_guardian(body: GuardianIn, c: Caller = Depends(caller)):
        need(c, "service", "dpo")
        f = fw(c)
        return children_call(lambda: f.children.record_guardian(
            resolve(f, body.external_id), f.principal(body.guardian_external_id), method=body.method,
            verification_ref=body.verification_ref, verified_by=c.label, issuer=body.issuer,
            relationship=body.relationship))

    @app.post("/v1/children/guardians/{guardian_id}/revoke")
    def child_guardian_revoke(guardian_id: str, body: RevokeGuardianIn, c: Caller = Depends(caller)):
        need(c, "service", "dpo")
        return children_call(lambda: fw(c).children.revoke_guardian(guardian_id, reason=body.reason, actor=c.label))

    @app.get("/v1/children/{external_id}")
    def child_view(external_id: str, c: Caller = Depends(caller)):
        need(c, "dpo", "reviewer")
        f = fw(c)
        return f.children.view(resolve(f, external_id))

    @app.post("/v1/withdrawals", status_code=202)
    def withdraw(body: WithdrawIn, c: Caller = Depends(caller),
                 idempotency_key: str | None = Header(default=None)):
        need(c, "principal", "service", "dpo")
        f = fw(c)
        check_self(c, body.external_id)
        return submit(c, f, resolve(f, body.external_id), withdraw_purpose=body.purpose_id,
                      verified_by=verified_by(c, body.verified_by), verification_ref=body.verification_ref,
                      idempotency_key=idempotency_key)

    @app.post("/v1/erasure-requests", status_code=202)
    def erasure(body: RequestIn, c: Caller = Depends(caller),
                idempotency_key: str | None = Header(default=None)):
        need(c, "principal", "service", "dpo")
        f = fw(c)
        if body.dry_run:
            need(c, "dpo")
            pid = resolve(f, body.external_id)
            return f.erase(pid, scope=body.scope, dry_run=True, requested_via="api-dry-run")
        check_self(c, body.external_id)
        return submit(c, f, resolve(f, body.external_id), scope=body.scope,
                      verified_by=verified_by(c, body.verified_by), verification_ref=body.verification_ref,
                      idempotency_key=idempotency_key)

    @app.get("/v1/erasure-requests")
    def erasure_list(status: str | None = None, sign_off: str | None = None, limit: int = 200,
                     c: Caller = Depends(caller)):
        """Recent erasure and withdrawal requests with their SLA and sign-off state (the console's queue)."""
        from ..core.models import utcnow
        from ..evidence.case import aware, iso

        need(c, "dpo", "reviewer")
        f = fw(c)
        now, out = utcnow(), []
        for r in f.store.recent_requests(min(max(limit, 1), 1000), status):
            st = f.cases.sign_off(r["request_id"])
            if sign_off and st["state"] != sign_off:
                continue
            due = aware(r["due_by"])
            out.append({"request_id": r["request_id"], "scope": r["scope"], "status": r["status"],
                        "requested_via": r["requested_via"], "received_at": iso(r["received_at"]),
                        "due_by": iso(r["due_by"]), "completed_at": iso(r["completed_at"]),
                        "overdue": bool(due and not r["completed_at"] and due < now),
                        "sign_off": st["state"], "approvals": len(st["approvals"]), "required": st["required"]})
        return out

    @app.get("/v1/principals/{external_id}/overview")
    def principal_overview(external_id: str, c: Caller = Depends(caller)):
        """One person for the DPO: consents and their signed history, status, lineage, cases. Ids, no values."""
        from ..evidence.case import iso

        need(c, "dpo")
        f = fw(c)
        pid = resolve(f, external_id)

        def clean(d):
            return {k: (iso(v) if hasattr(v, "isoformat") else v) for k, v in d.items()}
        return {"principal_id": pid,
                "consents": [clean(x) for x in f.store.consents_for(pid)],
                "consent_history": {"events": f.consent_history.events(pid)[-100:],
                                    "verify": f.consent_history.verify(pid)},
                "children": f.children.view(pid),
                "lineage": f.lineage(pid),
                "rights_cases": f.rights.list(principal_id=pid),
                "erasure_requests": [clean({k: r[k] for k in ("request_id", "scope", "status", "received_at",
                                                              "completed_at")})
                                     for r in f.store.recent_requests(100, principal_id=pid)]}

    @app.get("/v1/erasure-requests/{request_id}")
    def status(request_id: str, c: Caller = Depends(caller)):
        f = fw(c)
        r = own_or_dpo(c, f, request_id)
        out = {"request": {k: r[k] for k in ("request_id", "scope", "status", "received_at", "due_by",
                                             "completed_at", "verified_by", "verification_ref")}}
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

    # ---- case records and evidence (docs/evidence.md) ----------------------
    def evidence_call(fn):
        from ..evidence.case import EvidenceError

        try:
            return fn()
        except KeyError as e:
            raise HTTPException(404, str(e)) from e
        except EvidenceError as e:
            raise HTTPException(422, str(e)) from e

    @app.get("/v1/erasure-requests/{request_id}/case")
    def case(request_id: str, c: Caller = Depends(caller)):
        need(c, "dpo", "reviewer")
        return evidence_call(lambda: fw(c).case(request_id))

    @app.post("/v1/erasure-requests/{request_id}/manual-actions", status_code=201)
    def manual_action(request_id: str, body: ManualActionIn, c: Caller = Depends(caller)):
        need(c, "dpo", "service")
        return evidence_call(lambda: fw(c).record_manual_action(request_id, c.label, **body.model_dump()))

    @app.post("/v1/erasure-requests/{request_id}/reviews", status_code=201)
    def review(request_id: str, body: ReviewIn, c: Caller = Depends(caller)):
        need(c, "reviewer", "dpo")
        role = "reviewer" if "reviewer" in c.roles else "dpo"
        return evidence_call(lambda: fw(c).review(request_id, c.label, decision=body.decision,
                                                  checklist=body.checklist, notes=body.notes, role=role))

    @app.get("/v1/erasure-requests/{request_id}/evidence")
    def evidence(request_id: str, c: Caller = Depends(caller)):
        from fastapi.responses import Response

        need(c, "dpo", "reviewer")
        out = evidence_call(lambda: fw(c).export_evidence(request_id))
        return Response(out["data"], media_type="application/zip",
                        headers={"Content-Disposition": f'attachment; filename="{request_id}-evidence.zip"'})

    @app.get("/v1/audit-pack")
    def audit(start: str, end: str, include_cases: bool = True, c: Caller = Depends(caller)):
        from fastapi.responses import Response

        from ..evidence.audit import parse_day

        need(c, "dpo", "reviewer")
        try:
            s0, e0 = parse_day(start), parse_day(end)
        except ValueError as e:
            raise HTTPException(422, "start and end must be ISO dates (YYYY-MM-DD)") from e
        out = fw(c).export_audit_pack(s0, e0, include_cases=include_cases)
        return Response(out["data"], media_type="application/zip",
                        headers={"Content-Disposition": f'attachment; filename="audit-pack-{start}-{end}.zip"'})

    # ---- personal data breach (docs/breach.md) -----------------------------
    def breach_call(fn):
        from ..breach import BreachError

        try:
            return fn()
        except BreachError as e:
            raise HTTPException(404 if str(e).startswith("unknown breach") else 422, str(e)) from e

    @app.post("/v1/breaches", status_code=201)
    def breach_assess(body: BreachIn, c: Caller = Depends(caller)):
        """Assess a breach: affected people, exposure, processors and Rule 7 deadlines (signed, stored)."""
        need(c, "dpo")
        return breach_call(lambda: fw(c).breach.assess(assessed_by=c.label, **body.model_dump()))

    @app.get("/v1/breaches")
    def breach_list(c: Caller = Depends(caller)):
        need(c, "dpo", "reviewer")
        return fw(c).breach.list()

    @app.get("/v1/breaches/{breach_id}")
    def breach_show(breach_id: str, c: Caller = Depends(caller)):
        need(c, "dpo", "reviewer")
        return breach_call(lambda: fw(c).breach.get(breach_id))

    @app.get("/v1/breaches/{breach_id}/drafts")
    def breach_drafts(breach_id: str, c: Caller = Depends(caller)):
        """Draft Board intimations (Markdown) and one notice per affected Data Principal, for the DPO to complete."""
        need(c, "dpo")
        return breach_call(lambda: fw(c).breach.drafts(breach_id))

    @app.get("/v1/breaches/{breach_id}/verify")
    def breach_verify(breach_id: str, c: Caller = Depends(caller)):
        need(c, "dpo", "reviewer")
        return breach_call(lambda: fw(c).breach.verify(breach_id))

    @app.get("/v1/breaches/{breach_id}/bundle")
    def breach_bundle(breach_id: str, c: Caller = Depends(caller)):
        from fastapi.responses import Response

        need(c, "dpo", "reviewer")
        out = breach_call(lambda: fw(c).breach.export(breach_id))
        return Response(out["data"], media_type="application/zip",
                        headers={"Content-Disposition": f'attachment; filename="{breach_id}.zip"'})

    # ---- rights workflow (docs/rights.md) ----------------------------------
    _notice_cache: dict = {}

    def rights_call(fn):
        from ..core.idempotency import IdempotencyConflict
        from ..rights.desk import RightsError
        from ..rights.rules import RuleError

        try:
            return fn()
        except KeyError as e:
            raise HTTPException(404, str(e)) from e
        except IdempotencyConflict as e:
            raise HTTPException(409, str(e)) from e
        except (RightsError, RuleError, ValueError) as e:
            raise HTTPException(422, str(e)) from e

    def own_rights_case(c: Caller, f: DataRightsFramework, case_id: str) -> dict:
        case = f.store.get_rights_case(case_id)
        if not case:
            raise HTTPException(404, "unknown rights case")
        if c.has("dpo", "service", "reviewer"):
            return case
        if "principal" in c.roles and c.subject and f.vault.resolve_principal(c.subject, create=False) == case["principal_id"]:
            return case
        raise HTTPException(403)

    @app.get("/v1/rights/notice")
    def rights_notice(format: str = "json"):
        """Public: the Rule 14(1) notice (how to make requests, identifiers, response periods)."""
        from fastapi.responses import HTMLResponse

        from ..rights.notice import notice_html, published_means

        if "notice" not in _notice_cache:      # built once: configuration does not change while running
            n0 = published_means(dpdp if dpdp is not None else DataRightsFramework(cfg))
            n0.pop("gaps", None)
            _notice_cache["notice"] = n0
        n = dict(_notice_cache["notice"])
        return HTMLResponse(notice_html(n)) if format == "html" else n

    @app.post("/v1/rights-requests", status_code=202)
    def rights_submit(body: RightsIn, c: Caller = Depends(caller), idempotency_key: str | None = Header(default=None)):
        need(c, "principal", "service", "dpo")
        if body.on_behalf_of and not c.has("service", "dpo"):
            raise HTTPException(403, "nominee requests are submitted by a service or the DPO after verifying the nominee")
        f = fw(c)
        check_self(c, body.external_id)
        pid = resolve(f, body.external_id)
        return rights_call(lambda: f.rights.submit(
            body.type, pid, requested_by=c.label, verified_by=verified_by(c, body.verified_by),
            verification_ref=body.verification_ref, channel=body.channel, on_behalf_of=body.on_behalf_of,
            idempotency_key=idempotency_key, **body.details))

    @app.get("/v1/rights-requests")
    def rights_list(type: str | None = None, status: str | None = None, overdue: bool = False,
                    c: Caller = Depends(caller)):
        need(c, "dpo", "reviewer")
        return fw(c).rights.list(type=type, status=status, overdue=overdue)

    @app.get("/v1/rights-requests/{case_id}")
    def rights_get(case_id: str, c: Caller = Depends(caller)):
        f = fw(c)
        own_rights_case(c, f, case_id)
        staff = c.has("dpo", "reviewer")
        return rights_call(lambda: f.rights.view(case_id, reveal="full" if staff or "principal" in c.roles else "none",
                                                 for_principal=None if staff else "self"))

    @app.post("/v1/rights-requests/{case_id}/decision")
    def rights_decide(case_id: str, body: DecisionIn, c: Caller = Depends(caller)):
        need(c, "reviewer", "dpo")
        return rights_call(lambda: fw(c).rights.decide(case_id, c.label, body.decision, body.reason))

    @app.post("/v1/rights-requests/{case_id}/response")
    def rights_respond(case_id: str, body: GrievanceResponseIn, c: Caller = Depends(caller)):
        need(c, "dpo")
        return rights_call(lambda: fw(c).rights.respond(case_id, c.label, body.status, body.response))

    @app.get("/v1/rights-requests/{case_id}/access-report")
    def rights_access_report(case_id: str, format: str = "json", c: Caller = Depends(caller)):
        from fastapi.responses import HTMLResponse

        from ..rights.access import access_html

        f = fw(c)
        case = own_rights_case(c, f, case_id)
        if not (c.has("dpo") or "principal" in c.roles):
            raise HTTPException(403, "the access report goes to the Data Principal (or the DPO)")
        rep = rights_call(lambda: f.rights.access_report(case["case_id"]))
        return HTMLResponse(access_html(rep)) if format == "html" else rep

    @app.get("/v1/principals/{principal_id}/lineage")
    def lineage(principal_id: str, c: Caller = Depends(caller)):
        need(c, "dpo")
        return fw(c).lineage(principal_id)

    @app.get("/v1/sla")
    def sla(c: Caller = Depends(caller)):
        need(c, "dpo")
        f = fw(c)
        return {"open_requests": f.sla_counts(), "rights_cases": f.rights.sla_counts(), "jobs": f.queue.counts()}

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


def _mount_docs(app: FastAPI) -> None:
    """The interactive /docs page. Its Swagger UI 5 scripts are served from the package (fastapi-offline) when
    installed, so the page works on networks that block public CDNs (common in banks and hospitals); otherwise
    they come from the CDN."""
    import os

    from fastapi.openapi.docs import get_swagger_ui_html

    js = css = None
    try:
        import fastapi_offline
        from fastapi.staticfiles import StaticFiles

        static = os.path.join(os.path.dirname(fastapi_offline.__file__), "static")
        if os.path.exists(os.path.join(static, "swagger-ui-bundle.js")):
            app.mount("/docs-assets", StaticFiles(directory=static), name="docs-assets")
            js, css = "/docs-assets/swagger-ui-bundle.js", "/docs-assets/swagger-ui.css"
    except ImportError:
        pass

    @app.get("/docs", include_in_schema=False)
    def docs():
        kw = {"swagger_js_url": js, "swagger_css_url": css} if js else {}
        return get_swagger_ui_html(openapi_url=app.openapi_url, title=f"{app.title} - API", **kw)


CONSOLE_HEADERS = {
    # The console is static and loads nothing from elsewhere: no inline script, no third-party origins.
    "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' blob: data:; "
                               "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
    "Cache-Control": "no-store",
}


def _mount_console(app: FastAPI) -> None:
    """The DPO console (docs/console.md): static files at /console. It holds no data and no secrets; every screen
    calls this API with the signed-in user's own credential, so the API's roles decide what each person sees."""
    from fastapi.responses import RedirectResponse
    from fastapi.staticfiles import StaticFiles

    static = os.path.join(os.path.dirname(os.path.dirname(__file__)), "console")

    @app.get("/console", include_in_schema=False)
    def console_root():
        return RedirectResponse("/console/")

    app.mount("/console/", StaticFiles(directory=static, html=True), name="console")

    @app.middleware("http")
    async def _console_headers(request: Request, call_next):
        resp = await call_next(request)
        if request.url.path.startswith("/console"):
            for k, v in CONSOLE_HEADERS.items():
                resp.headers[k] = v
        return resp


def default_app() -> FastAPI:
    return create_app(config=FrameworkConfig.load(os.environ.get("DPDP_CONFIG", "config/dpdp.local.yaml")))
