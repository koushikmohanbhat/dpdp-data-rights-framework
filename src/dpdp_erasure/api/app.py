"""REST API for Data Principal rights + DPO operations (FastAPI).

    uvicorn dpdp_erasure.api.app:default_app --factory   (reads DPDP_CONFIG)
    or: dpdp-erasure serve -c config/dpdp.local.yaml
"""
from __future__ import annotations

import json
import os
import threading

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from ..kit import ErasureKit


class ErasureIn(BaseModel):
    external_id: str | None = None
    principal_id: str | None = None
    scope: str = "full"
    dry_run: bool = False
    requested_via: str = "api"


class ConsentIn(BaseModel):
    external_id: str
    purpose_id: str
    element_types: list[str] | None = None
    notice_version: str = "v1"
    consent_manager_ref: str | None = None


class WithdrawIn(BaseModel):
    external_id: str
    purpose_id: str
    erase: bool = True


def create_app(kit: ErasureKit) -> FastAPI:
    app = FastAPI(title="GenAI DPDP Erasure Kit", version="0.1.0")
    results: dict[str, dict] = {}

    def _pid(external_id: str | None, principal_id: str | None) -> str:
        if principal_id:
            return principal_id
        if not external_id:
            raise HTTPException(400, "external_id or principal_id required")
        pid = kit.vault.resolve_principal(external_id, create=False)
        if not pid:
            raise HTTPException(404, "unknown data principal")
        return pid

    @app.get("/healthz")
    def health():
        return {"ok": True, "stats": kit.store.stats()}

    @app.post("/v1/consents")
    def grant(c: ConsentIn):
        pid = kit.principal(c.external_id)
        ids = kit.grant_consent(pid, c.purpose_id, c.element_types, notice_version=c.notice_version,
                                consent_manager_ref=c.consent_manager_ref)
        return {"principal_id": pid, "consent_ids": ids}

    @app.post("/v1/consents/withdraw")
    def withdraw(w: WithdrawIn):
        pid = _pid(w.external_id, None)
        return kit.withdraw_consent(pid, w.purpose_id, erase=w.erase)

    @app.post("/v1/erasure-requests", status_code=202)
    def submit(e: ErasureIn):
        pid = _pid(e.external_id, e.principal_id)
        req = kit.orchestrator.submit(pid, e.scope, e.dry_run, e.requested_via)
        if e.dry_run:
            results[req.request_id] = kit.orchestrator.run(req)
        else:
            threading.Thread(target=lambda: results.__setitem__(req.request_id, kit.orchestrator.run(req)),
                             daemon=True).start()
        return {"request_id": req.request_id, "due_by": req.due_by.isoformat()}

    @app.get("/v1/erasure-requests/{request_id}")
    def status(request_id: str):
        r = kit.store.get_request(request_id)
        if not r:
            raise HTTPException(404)
        return {"request": r, "actions": kit.store.actions_for(request_id), "result": results.get(request_id)}

    @app.get("/v1/erasure-requests/{request_id}/certificate")
    def certificate(request_id: str):
        c = kit.store.get_certificate(request_id)
        if not c:
            raise HTTPException(404, "no certificate yet")
        return {"sha256": c["sha256"], "prev_sha256": c["prev_sha256"], "payload": json.loads(c["payload"])}

    @app.get("/v1/principals/{principal_id}/lineage")
    def lineage(principal_id: str):
        return kit.lineage(principal_id)

    return app


def default_app() -> FastAPI:
    return create_app(ErasureKit.from_yaml(os.environ.get("DPDP_CONFIG", "config/dpdp.local.yaml")))

