"""Auth, verification, durable queue + resume, signed certificates, break-glass, guardrails, tenancy."""
import time
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from dpdp_rights import DataRightsFramework, FrameworkConfig
from dpdp_rights.api.app import create_app
from dpdp_rights.core.models import utcnow
from dpdp_rights.security.auth import Authenticator, AuthError, hash_api_key
from dpdp_rights.security.breakglass import AccessDenied
from dpdp_rights.security.guardrails import ProductionGuardrailError, production_issues
from dpdp_rights.security.verification import VerificationError


def _cfg(tmp, **extra):
    base = {
        "provider": {"type": "echo"},
        "vault": {"local_master_key_path": str(tmp / "m.key"), "sealed_key_wrapper": "local",
                  "sealed_local_master_key_path": str(tmp / "s.key")},
        "lineage": {"url": f"sqlite:///{tmp}/l.db"},
        "purposes": [{"id": "service"}, {"id": "marketing"},
                     {"id": "kyc", "legal_basis": "legitimate_use", "legal_hold_basis": "statute"}],
        "connectors": [{"name": "records", "type": "sql_table",
                        "options": {"url": f"sqlite:///{tmp}/app.db", "table": "records", "content_column": "body",
                                    "principal_column": "principal_id"}}],
        "certificates": {"signer": "local", "local_key_path": str(tmp / "sign.key"),
                         "archive": "local", "archive_uri": str(tmp / "certs")},
    }
    base.update(extra)
    return FrameworkConfig.from_dict(base)


@pytest.fixture
def fw(workdir):
    tmp, _ = workdir
    return DataRightsFramework(_cfg(tmp))


def _person(f, db, ext="p1", email="p1@x.in"):
    pid = f.principal(ext)
    f.register_identifier(pid, "EMAIL", email)
    f.grant_consent(pid, "service")
    f.grant_consent(pid, "marketing")
    with f.context(pid, purpose="service"):
        s = f.protect(f"mail {email} please")
        db.execute("INSERT INTO records VALUES (?,?,?)", (ext, pid, s.text))
        db.commit()
        f.track_artifact("record", "records", {"id": ext}, content=s.text, element_ids=s.element_ids)
    return pid


# ---- auth ------------------------------------------------------------------
def test_api_key_and_roles():
    from dpdp_rights.core.config import AuthConfig

    a = Authenticator(AuthConfig(mode="api_key", api_keys=[{"name": "crm", "sha256": hash_api_key("s3cret"),
                                                            "roles": ["service"], "tenant": "acme"}]))
    c = a.authenticate({"X-Api-Key": "s3cret"})
    assert c.has("service") and not c.has("dpo") and c.tenant == "acme"
    with pytest.raises(AuthError):
        a.authenticate({"X-Api-Key": "wrong"})
    with pytest.raises(AuthError):
        a.authenticate({})


def test_oidc_jwt_verification():
    from dpdp_rights.core.config import AuthConfig

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    class Jwk:
        def get_signing_key_from_jwt(self, _t):
            class K:
                pass
            k = K()
            k.key = key.public_key()
            return k

    cfg = AuthConfig(mode="oidc", oidc={"issuer": "https://idp", "audience": "dpdp-api"})
    a = Authenticator(cfg, jwk_client=Jwk())
    now = int(time.time())
    tok = jwt.encode({"iss": "https://idp", "aud": "dpdp-api", "sub": "app-1001", "iat": now, "exp": now + 60,
                      "roles": ["principal"]}, key, algorithm="RS256")
    c = a.authenticate({"Authorization": f"Bearer {tok}"})
    assert c.subject == "app-1001" and c.roles == {"principal"}
    bad = jwt.encode({"iss": "https://evil", "aud": "dpdp-api", "sub": "x", "iat": now, "exp": now + 60},
                     key, algorithm="RS256")
    with pytest.raises(AuthError):
        a.authenticate({"Authorization": f"Bearer {bad}"})


def test_api_enforces_auth_roles_and_self_service(workdir):
    tmp, db = workdir
    cfg = _cfg(tmp, api={"auth": {"mode": "api_key", "api_keys": [
        {"name": "crm", "sha256": hash_api_key("svc"), "roles": ["service"]},
        {"name": "dpo1", "sha256": hash_api_key("dpo"), "roles": ["dpo"]},
        {"name": "dpo2", "sha256": hash_api_key("appr"), "roles": ["approver"]}]}})
    f = DataRightsFramework(cfg)
    pid = _person(f, db)
    c = TestClient(create_app(f))
    assert c.post("/v1/erasure-requests", json={"external_id": "p1"}).status_code == 401
    assert c.get(f"/v1/principals/{pid}/lineage", headers={"x-api-key": "svc"}).status_code == 403
    assert c.get(f"/v1/principals/{pid}/lineage", headers={"x-api-key": "dpo"}).status_code == 200

    # service submits -> OTP to the registered email -> verify -> worker processes
    r = c.post("/v1/erasure-requests", json={"external_id": "p1"}, headers={"x-api-key": "svc", "Idempotency-Key": "k1"})
    assert r.status_code == 202 and r.json()["status"] == "pending_verification"
    assert r.json()["verification"]["destination"] == "p***@x.in"
    rid = r.json()["request_id"]
    again = c.post("/v1/erasure-requests", json={"external_id": "p1"}, headers={"x-api-key": "svc", "Idempotency-Key": "k1"})
    assert again.json()["request_id"] == rid and again.json()["duplicate"]
    code = f.verification.notifier.sent[-1][2].split("is ")[1][:6]
    assert c.post(f"/v1/erasure-requests/{rid}/verify", json={"code": "000000" if code != "000000" else "111111"},
                  headers={"x-api-key": "svc"}).status_code == 422
    assert c.post(f"/v1/erasure-requests/{rid}/verify", json={"code": code}, headers={"x-api-key": "svc"}).json()["status"] == "received"
    assert f.store.get_request(rid)["status"] == "received"          # nothing erased until a worker runs
    jobs = f.process_jobs()
    assert jobs[0]["ok"] and jobs[0]["result"]["status"] == "completed"
    v = c.get(f"/v1/erasure-requests/{rid}/certificate/verify", headers={"x-api-key": "dpo"}).json()
    assert v["hash_ok"] and v["chain_ok"] and v["signature_ok"] and v["archive_uri"]


def test_dpo_attested_needs_evidence_and_withdrawal_flow(workdir):
    tmp, db = workdir
    f = DataRightsFramework(_cfg(tmp))
    pid = _person(f, db)
    with pytest.raises(VerificationError):
        f.submit_request(pid, verification="dpo_attested")
    out = f.submit_request(pid, withdraw_purpose="marketing", verification="dpo_attested",
                           evidence="VKYC-2026-0042", requested_by="api_key:dpo1")
    assert out["status"] == "received" and "job_id" in out
    f.process_jobs()
    assert f.store.active_consents(pid, "marketing") == []
    assert f.store.active_consents(pid, "service") == ["*"]
    assert f.store.get_request(out["request_id"])["verification_method"] == "dpo_attested"


def test_otp_locks_after_max_attempts(fw, workdir):
    _, db = workdir
    pid = _person(fw, db)
    rid = fw.submit_request(pid)["request_id"]
    for _ in range(4):
        assert fw.verification.verify(rid, "999999") is False
    with pytest.raises(VerificationError):
        fw.verification.verify(rid, "999999")
    with pytest.raises(VerificationError):
        fw.confirm_request(rid, "123456")


# ---- queue / resume ------------------------------------------------------------
def test_queue_lease_retry_and_idempotency(fw):
    q = fw.queue
    j1 = q.enqueue("purge_escrows", {}, idempotency_key="daily-2026-11-06")
    assert q.enqueue("purge_escrows", {}, idempotency_key="daily-2026-11-06") == j1
    job = q.claim()
    assert job["job_id"] == j1 and q.claim() is None              # leased: nobody else gets it
    assert q.fail(j1, "boom") == "retrying"
    from sqlalchemy import update

    from dpdp_rights.lineage.store import job as job_t
    with fw.store.engine.begin() as c:
        c.execute(update(job_t).values(run_after=utcnow() - timedelta(seconds=1)))
    assert q.claim()["attempts"] == 2


def test_crashed_run_resumes_without_redoing_work(fw, workdir):
    _, db = workdir
    pid = _person(fw, db)
    out = fw.submit_request(pid, verification="dpo_attested", evidence="E1")
    real_verify = fw.orchestrator.verify
    state = {"crashed": False}

    def crash_once(ctx, full):          # process dies after deletes + key shred, before verification
        if not state["crashed"]:
            state["crashed"] = True
            raise RuntimeError("worker killed")
        return real_verify(ctx, full)

    fw.orchestrator.verify = crash_once
    first = fw.process_jobs()
    assert first[0]["ok"] is False and first[0]["state"] == "retrying"
    assert not fw.vault.has_key(pid)                              # shred already happened
    from sqlalchemy import update

    from dpdp_rights.lineage.store import job as job_t
    with fw.store.engine.begin() as c:
        c.execute(update(job_t).values(run_after=utcnow() - timedelta(seconds=1)))
    second = fw.process_jobs()
    assert second[0]["ok"] and second[0]["result"]["status"] == "completed"
    acts = fw.store.actions_for(out["request_id"])
    assert sum(1 for a in acts if a["artifact_id"] == "vault") == 1      # vault shredded exactly once
    assert sum(1 for a in acts if a["store"] == "records") == 1           # record deleted exactly once
    from dpdp_rights.core.models import ErasureRequest
    again = fw.orchestrator.run(ErasureRequest(out["request_id"], pid, "full"))
    assert again.get("already_completed")


# ---- break-glass ----------------------------------------------------------------
def test_break_glass_two_person_rule_and_audit(workdir):
    tmp, db = workdir
    f = DataRightsFramework(_cfg(tmp))
    pid = f.principal("k1")
    with f.context(pid, purpose="kyc"):
        s = f.protect("PAN ABCPR1234K")
        db.execute("INSERT INTO records VALUES ('k1', ?, ?)", (pid, s.text))
        db.commit()
        f.track_artifact("record", "records", {"id": "k1"}, content=s.text, element_ids=s.element_ids)
    f.erase(pid)
    tok = s.text.split()[-1]
    assert f.vault.reveal(tok) == "[ERASED]"
    g = f.break_glass.request(pid, "dpo:asha", "Court order 12/2026", "LEGAL-881")
    with pytest.raises(AccessDenied):
        f.break_glass.read(g["grant_id"], "dpo:asha", [tok])          # not approved yet
    with pytest.raises(AccessDenied):
        f.break_glass.approve(g["grant_id"], "dpo:asha")              # self-approval
    f.break_glass.approve(g["grant_id"], "approver:ravi")
    with pytest.raises(AccessDenied):
        f.break_glass.read(g["grant_id"], "approver:ravi", [tok])     # only the requester
    assert f.break_glass.read(g["grant_id"], "dpo:asha", [tok]) == {tok: "ABCPR1234K"}
    outcomes = [e["outcome"] for e in f.break_glass.audit(g["grant_id"])]
    assert outcomes.count("denied") == 3 and "allowed" in outcomes


def test_sealed_keys_use_separate_kek_and_are_never_cached(fw):
    pid = fw.principal("s1")
    tok = fw.vault.tokenize(pid, "EMAIL", "s1@x.in")
    fw.vault.shred(pid, escrow=True)
    assert f"escrow_{pid}" not in fw.vault._cache
    assert fw.vault.sealed_wrapper is not fw.vault.wrapper
    assert fw.vault.detokenize(tok, privileged=True) == "s1@x.in"
    assert f"escrow_{pid}" not in fw.vault._cache


def test_dek_cache_expires(workdir):
    tmp, _ = workdir
    f = DataRightsFramework(_cfg(tmp, vault={"local_master_key_path": str(tmp / "m.key"), "cache_ttl_seconds": 0}))
    pid = f.principal("t1")
    f.vault.tokenize(pid, "EMAIL", "t@x.in")
    entry = f.vault._cache.get(pid)
    assert entry is None or entry[1] <= time.monotonic()


# ---- certificates -------------------------------------------------------------------
def test_signed_certificate_detects_tampering(fw, workdir):
    _, db = workdir
    pid = _person(fw, db)
    res = fw.erase(pid)
    assert res["certificate_signature"] and res["certificate_archive"]
    assert fw.verify_certificate(res["request_id"])["signature_ok"] is True
    from sqlalchemy import update

    from dpdp_rights.lineage.store import erasure_certificate
    with fw.store.engine.begin() as c:
        c.execute(update(erasure_certificate).values(payload=erasure_certificate.c.payload + " "))
    v = fw.verify_certificate(res["request_id"])
    assert v["hash_ok"] is False and v["signature_ok"] is False


# ---- guardrails & tenancy --------------------------------------------------------------
def test_production_guardrails_block_unsafe_config(workdir):
    tmp, _ = workdir
    cfg = _cfg(tmp, environment="production")
    errors = [m for lvl, m in production_issues(cfg) if lvl == "error"]
    assert any("key_wrapper=local" in m for m in errors) and any("auth.mode=none" in m for m in errors)
    assert any("NER" in m for m in errors) and any("SQLite" in m for m in errors)
    with pytest.raises(ProductionGuardrailError):
        DataRightsFramework(cfg)


def test_tenants_are_isolated(workdir):
    tmp, _ = workdir
    import yaml
    for t in ("acme", "globex"):
        (tmp / t).mkdir()
        c = _cfg(tmp / t).model_dump()
        (tmp / f"{t}.yaml").write_text(yaml.safe_dump(c))
    root = _cfg(tmp, tenants={"acme": {"config": str(tmp / "acme.yaml")}, "globex": {"config": str(tmp / "globex.yaml")}},
                api={"auth": {"mode": "api_key", "api_keys": [
                    {"name": "a", "sha256": hash_api_key("ka"), "roles": ["service", "dpo"], "tenant": "acme"},
                    {"name": "g", "sha256": hash_api_key("kg"), "roles": ["service", "dpo"], "tenant": "globex"}]}})
    c = TestClient(create_app(config=root))
    pid = c.post("/v1/consents", json={"external_id": "cust-1", "purpose_id": "service"},
                 headers={"x-api-key": "ka"}).json()["principal_id"]
    assert c.get(f"/v1/principals/{pid}/lineage", headers={"x-api-key": "ka"}).status_code == 200
    r = c.post("/v1/erasure-requests", json={"external_id": "cust-1"}, headers={"x-api-key": "kg"})
    assert r.status_code == 404                                     # globex cannot see acme's principal


def test_logging_filter_masks_without_context(fw, workdir, caplog):
    import logging
    tmp, _ = workdir
    lg = logging.getLogger("nocontext")
    h = logging.FileHandler(tmp / "n.log")
    h.addFilter(fw.logging_filter())
    lg.addHandler(h)
    lg.warning("callback failed for 9876543210 / x@y.in")
    h.close()
    text = (tmp / "n.log").read_text()
    assert "9876543210" not in text and "[PHONE_IN]" in text and "[EMAIL]" in text


def test_sla_counts(fw, workdir):
    _, db = workdir
    pid = _person(fw, db)
    out = fw.submit_request(pid)
    from sqlalchemy import update

    from dpdp_rights.lineage.store import erasure_request
    with fw.store.engine.begin() as c:
        c.execute(update(erasure_request).values(due_by=datetime.now(timezone.utc) - timedelta(days=1)))
    assert fw.sla_counts()["overdue"] == 1 and out["status"] == "pending_verification"
