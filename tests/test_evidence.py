"""Evidence and audit pack: case log, reviewer sign-off, signed bundles, audit packs."""
import io
import json
import zipfile
from datetime import timedelta

import pytest
from _db import lineage_url
from fastapi.testclient import TestClient

from dpdp_rights import DataRightsFramework, FrameworkConfig
from dpdp_rights.api.app import create_app
from dpdp_rights.core.models import utcnow
from dpdp_rights.evidence import EvidenceError, verify_bundle
from dpdp_rights.evidence.audit import audit_pack
from dpdp_rights.security.auth import hash_api_key
from dpdp_rights.security.guardrails import production_issues

ALL = {"requester_verified": True, "scope_matches_request": True, "exceptions_justified": True,
       "verification_reviewed": True, "manual_systems_done": True}


def _cfg(tmp, **extra):
    base = {
        "provider": {"type": "echo"},
        "vault": {"local_master_key_path": str(tmp / "m.key")},
        "lineage": {"url": lineage_url(tmp)},
        "purposes": [{"id": "service"}, {"id": "marketing"}],
        "connectors": [{"name": "records", "type": "sql_table",
                        "options": {"url": f"sqlite:///{tmp}/app.db", "table": "records", "content_column": "body",
                                    "principal_column": "principal_id"}}],
        "certificates": {"signer": "local", "local_key_path": str(tmp / "sign.key")},
    }
    base.update(extra)
    return FrameworkConfig.from_dict(base)


@pytest.fixture
def fw(workdir):
    tmp, _ = workdir
    return DataRightsFramework(_cfg(tmp))


def _erased(f, db, ext="p1", requested_by="service:crm"):
    pid = f.principal(ext)
    f.grant_consent(pid, "service")
    with f.context(pid, purpose="service"):
        s = f.protect(f"mail {ext}@example.in, phone 9876543210")
        db.execute("INSERT INTO records VALUES (?,?,?)", (ext, pid, s.text))
        db.commit()
        f.track_artifact("record", "records", {"id": ext}, content=s.text, element_ids=s.element_ids)
    r = f.submit_request(pid, requested_by=requested_by, verified_by="branch:BLR-07", verification_ref="VKYC-0042")
    f.process_jobs()
    return pid, r["request_id"]


def test_case_record_has_everything_and_no_personal_data(fw, workdir):
    _, db = workdir
    pid, rid = _erased(fw, db)
    c = fw.case(rid)
    assert c["request"]["status"] == "completed" and c["request"]["verification_ref"] == "VKYC-0042"
    assert c["sla"]["met"] is True and c["certificate"]["check"]["signature_ok"] is True
    assert c["actions_by_store"]["records"] == {"delete": 1}
    assert c["sign_off"]["state"] == "pending" and c["case_log_check"]["ok"]
    text = json.dumps(c, default=str)
    assert "9876543210" not in text and "p1@example.in" not in text


def test_review_rules_separation_of_duties_and_personal_data(fw, workdir):
    _, db = workdir
    _, rid = _erased(fw, db)
    with pytest.raises(EvidenceError, match="submitted"):
        fw.review(rid, "service:crm", decision="approved", checklist=ALL)
    fw.record_manual_action(rid, "ops:meena", system="Core policy admin", action="deleted", reference="CHG-1201")
    with pytest.raises(EvidenceError, match="manual actions"):
        fw.review(rid, "ops:meena", decision="approved", checklist=ALL)
    with pytest.raises(EvidenceError, match="missing"):
        fw.review(rid, "dpo:asha", decision="approved", checklist={"requester_verified": True})
    with pytest.raises(EvidenceError, match="failed checklist"):
        fw.review(rid, "dpo:asha", decision="approved", checklist=ALL | {"verification_reviewed": False})
    with pytest.raises(EvidenceError, match="unknown checklist"):
        fw.review(rid, "dpo:asha", decision="approved", checklist=ALL | {"made_up": True})
    with pytest.raises(EvidenceError, match="personal data"):
        fw.review(rid, "dpo:asha", decision="needs_info", notes="call her on 9876543210")
    with pytest.raises(EvidenceError, match="personal data"):
        fw.record_manual_action(rid, "ops:meena", system="CRM", action="deleted", reference="priya@example.in")
    with pytest.raises(EvidenceError, match="notes are required"):
        fw.review(rid, "dpo:asha", decision="rejected")
    out = fw.review(rid, "dpo:asha", decision="approved", checklist=ALL | {"manual_systems_done": "n/a"})
    assert out["signed"] and out["sign_off"]["state"] == "approved"
    assert fw.case(rid)["case_log_check"] == {"ok": True, "events": 2, "anchored_to": "certificate",
                                             "broken_at": None, "signatures_ok": True}


def test_later_manual_action_makes_approval_stale_and_rejection_wins(workdir):
    tmp, db = workdir
    f = DataRightsFramework(_cfg(tmp, evidence={"required_approvals": 2}))
    _, rid = _erased(f, db)
    assert f.review(rid, "dpo:asha", decision="approved", checklist=ALL)["sign_off"]["state"] == "pending"
    assert f.review(rid, "reviewer:ravi", decision="approved", checklist=ALL)["sign_off"]["state"] == "approved"
    f.record_manual_action(rid, "ops:meena", system="Paper files", action="deleted", reference="SHRED-77")
    so = f.cases.sign_off(rid)
    assert so["state"] == "pending" and so["stale_approvals"] == ["dpo:asha", "reviewer:ravi"]
    f.review(rid, "dpo:asha", decision="approved", checklist=ALL)
    assert f.review(rid, "reviewer:ravi", decision="rejected", notes="CHG ticket not closed")["sign_off"]["state"] == "rejected"


def test_no_review_before_processing_and_failed_cannot_be_approved(fw, workdir):
    _, db = workdir
    pid = fw.principal("q1")
    r = fw.submit_request(pid, requested_by="service:crm")
    with pytest.raises(EvidenceError, match="after processing"):
        fw.review(r["request_id"], "dpo:asha", decision="approved", checklist=ALL)
    fw.store.set_request_status(r["request_id"], "failed")
    with pytest.raises(EvidenceError, match="failed request"):
        fw.review(r["request_id"], "dpo:asha", decision="approved", checklist=ALL)
    ev = fw.review(r["request_id"], "dpo:asha", decision="needs_info", notes="worker error; see INC-55")
    assert ev["prev_sha256"] != "" and fw.case(r["request_id"])["case_log_check"]["anchored_to"] == "request"


def test_exceptions_need_notes_to_approve(fw, workdir):
    _, db = workdir
    _, rid = _erased(fw, db)
    fw.store.set_request_status(rid, "completed_with_exceptions")
    with pytest.raises(EvidenceError, match="notes are required to approve"):
        fw.review(rid, "dpo:asha", decision="approved", checklist=ALL)
    assert fw.review(rid, "dpo:asha", decision="approved", checklist=ALL,
                     notes="KYC hold per legal opinion LGL-12")["sign_off"]["state"] == "approved"


def test_case_log_tampering_is_detected(fw, workdir):
    _, db = workdir
    _, rid = _erased(fw, db)
    fw.record_manual_action(rid, "ops:meena", system="CRM", action="deleted", reference="CHG-1")
    fw.review(rid, "dpo:asha", decision="approved", checklist=ALL)
    from sqlalchemy import func, update

    from dpdp_rights.lineage.store import case_event
    with fw.store.engine.begin() as c:
        c.execute(update(case_event).where(case_event.c.kind == "review")
                  .values(body=func.replace(case_event.c.body, '"approved"', '"rejected"')))
    chk = fw.cases.verify_chain(rid)
    assert chk["ok"] is False and chk["broken_at"]
    with fw.store.engine.begin() as c:       # even a whitespace-only edit of the stored text is caught
        c.execute(update(case_event).where(case_event.c.kind == "manual_action")
                  .values(body=case_event.c.body.op("||")(" ")))
    first = fw.cases.events(rid)[0]
    assert first["kind"] == "manual_action" and fw.cases.verify_chain(rid)["broken_at"] == first["event_id"]


def test_evidence_bundle_verifies_offline_and_detects_changes(fw, workdir):
    tmp, db = workdir
    _, rid = _erased(fw, db)
    fw.review(rid, "dpo:asha", decision="approved", checklist=ALL)
    out = fw.export_evidence(rid, str(tmp / "case.zip"))
    names = set(zipfile.ZipFile(tmp / "case.zip").namelist())
    assert {"case.json", "case.md", "case.html", "certificate.json", "public_key.pem", "manifest.json",
            "manifest.sig"} <= names
    v = verify_bundle(str(tmp / "case.zip"))
    assert v["ok"] and v["signature_ok"] and v["certificate_signature_ok"] and v["case_log_ok"]
    assert v["key_pinned"] is False and "pin" in v["note"] and v["sign_off"] == "approved"
    fp = out["manifest"]["key_fingerprint"]
    assert verify_bundle(str(tmp / "case.zip"), fingerprint=fp)["key_pinned"] is True
    assert not verify_bundle(str(tmp / "case.zip"), fingerprint="0" * 64)["ok"]

    # change one file inside the zip -> hash mismatch
    src = zipfile.ZipFile(tmp / "case.zip")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for n in src.namelist():
            data = src.read(n)
            if n == "case.md":
                data += b"\nedited"
            z.writestr(n, data)
    bad = verify_bundle(buf.getvalue())
    assert not bad["ok"] and "file changed after signing: case.md" in bad["problems"]

    # re-sign with a different key: hashes and signature pass, but a pinned key catches it
    other = DataRightsFramework(_cfg(tmp, certificates={"signer": "local", "local_key_path": str(tmp / "other.key")}))
    forged = other.export_evidence(rid)["data"]
    assert not verify_bundle(forged, fingerprint=fp)["ok"]


def test_audit_pack_metrics_findings_and_chain(fw, workdir):
    tmp, db = workdir
    _, r1 = _erased(fw, db, "a1")
    _, r2 = _erased(fw, db, "a2")
    fw.review(r1, "dpo:asha", decision="approved", checklist=ALL)
    fw.store.set_request_status(r2, "completed_with_exceptions")
    pid3 = fw.principal("a3")
    r3 = fw.submit_request(pid3, requested_by="service:crm")["request_id"]
    from sqlalchemy import update

    from dpdp_rights.lineage.store import erasure_request
    with fw.store.engine.begin() as c:       # an open request past its due date
        c.execute(update(erasure_request).where(erasure_request.c.request_id == r3)
                  .values(due_by=utcnow() - timedelta(days=1)))
    start, end = utcnow() - timedelta(days=1), utcnow() + timedelta(days=1)
    rep = audit_pack(fw, start, end)
    m = rep["metrics"]
    assert m["requests_received"] == 3 and m["finished"] == 2 and m["completed_within_sla_pct"] == 100.0
    assert m["signed_off_pct"] == 50.0 and m["by_scope"] == {"full": 3, "purpose": 0}
    codes = {(f["code"], f["request_id"]) for f in rep["findings"]}
    assert ("overdue", r3) in codes and ("exceptions_unreviewed", r2) in codes
    assert rep["certificate_chain"] == {"certificates": 2, "hash_ok": True, "links_ok": True,
                                        "signatures_ok": True, "first_break": None}
    res = fw.export_audit_pack(start, end, str(tmp / "audit.zip"))
    names = zipfile.ZipFile(tmp / "audit.zip").namelist()
    assert f"cases/{r1}.json" in names and "audit.html" in names
    v = verify_bundle(str(tmp / "audit.zip"))
    assert v["ok"] and v["kind"] == "audit_pack"
    assert res["manifest"]["findings"]["error"] >= 1


def test_audit_pack_detects_broken_certificate_chain(fw, workdir):
    _, db = workdir
    _erased(fw, db, "b1")
    _, r2 = _erased(fw, db, "b2")
    from sqlalchemy import update

    from dpdp_rights.lineage.store import erasure_certificate
    with fw.store.engine.begin() as c:
        c.execute(update(erasure_certificate).where(erasure_certificate.c.request_id == r2).values(prev_sha256="f" * 64))
    rep = audit_pack(fw, utcnow() - timedelta(days=1), utcnow() + timedelta(days=1))
    assert rep["certificate_chain"]["links_ok"] is False
    assert any(f["code"] == "certificate_chain_broken" for f in rep["findings"])


def test_api_case_reviews_and_evidence(workdir):
    tmp, db = workdir
    f = DataRightsFramework(_cfg(tmp, api={"auth": {"mode": "api_key", "api_keys": [
        {"name": "crm", "sha256": hash_api_key("svc"), "roles": ["service"]},
        {"name": "asha", "sha256": hash_api_key("dpo"), "roles": ["dpo"]},
        {"name": "ravi", "sha256": hash_api_key("rev"), "roles": ["reviewer"]}]}}))
    pid = f.principal("p1")
    f.grant_consent(pid, "service")
    c = TestClient(create_app(f))
    r = c.post("/v1/erasure-requests", json={"external_id": "p1", "verification_ref": "V-1"},
               headers={"x-api-key": "svc"}).json()
    f.process_jobs()
    rid = r["request_id"]
    svc, dpo, rev = ({"x-api-key": k} for k in ("svc", "dpo", "rev"))
    assert c.get(f"/v1/erasure-requests/{rid}/case", headers=svc).status_code == 403
    assert c.get(f"/v1/erasure-requests/{rid}/case", headers=rev).json()["sign_off"]["state"] == "pending"
    ma = c.post(f"/v1/erasure-requests/{rid}/manual-actions", headers=svc,
                json={"system": "Branch paper file", "action": "deleted", "reference": "SHRED-9"})
    assert ma.status_code == 201
    assert c.post(f"/v1/erasure-requests/{rid}/manual-actions", headers=rev,
                  json={"system": "x", "action": "deleted", "reference": "y"}).status_code == 403
    bad = c.post(f"/v1/erasure-requests/{rid}/reviews", headers=rev, json={"decision": "approved"})
    assert bad.status_code == 422
    ok = c.post(f"/v1/erasure-requests/{rid}/reviews", headers=rev,
                json={"decision": "approved", "checklist": ALL})
    assert ok.status_code == 201 and ok.json()["sign_off"]["state"] == "approved"
    z = c.get(f"/v1/erasure-requests/{rid}/evidence", headers=dpo)
    assert z.headers["content-type"] == "application/zip" and verify_bundle(z.content)["ok"]
    day = utcnow().date()
    pack = c.get(f"/v1/audit-pack?start={day - timedelta(days=1)}&end={day + timedelta(days=1)}", headers=rev)
    assert pack.status_code == 200 and verify_bundle(pack.content)["kind"] == "audit_pack"
    assert c.get("/v1/audit-pack?start=bad&end=x", headers=rev).status_code == 422


def test_cli_case_review_evidence_and_audit_pack(workdir, capsys):
    tmp, db = workdir
    import yaml

    from dpdp_rights.cli import main
    cfgd = _cfg(tmp).model_dump(mode="json")
    (tmp / "c.yaml").write_text(yaml.safe_dump(cfgd))
    f = DataRightsFramework.from_yaml(str(tmp / "c.yaml"))
    _, rid = _erased(f, db)
    main(["-c", str(tmp / "c.yaml"), "case", "review", "--request-id", rid, "--reviewer", "dpo:asha",
          "--decision", "approved", "--check", "all=yes"])
    assert '"approved"' in capsys.readouterr().out
    main(["-c", str(tmp / "c.yaml"), "evidence", "export", "--request-id", rid, "--output", str(tmp / "e.zip")])
    with pytest.raises(SystemExit) as e:
        main(["evidence", "verify", str(tmp / "e.zip")])
    assert e.value.code == 0
    day = utcnow().date()
    with pytest.raises(SystemExit) as e:
        main(["-c", str(tmp / "c.yaml"), "audit-pack", "--from", str(day - timedelta(days=1)),
              "--to", str(day + timedelta(days=1)), "--output", str(tmp / "a.zip"), "--fail-on-errors"])
    assert e.value.code == 0 and "1 requests" in capsys.readouterr().out
    with pytest.raises(SystemExit, match="refused"):
        main(["-c", str(tmp / "c.yaml"), "case", "manual-action", "--request-id", rid, "--actor", "ops:x",
              "--system", "CRM", "--action", "burned", "--reference", "R-1"])


def test_notification_on_review_and_guardrails(workdir):
    tmp, db = workdir
    sent = []
    f = DataRightsFramework(_cfg(tmp, notifications=[{"type": "log", "events": ["case_reviewed"]}]))
    f.notifications.emit = lambda ev, p: sent.append((ev, p))
    f.cases.notifications = f.notifications
    _, rid = _erased(f, db)
    f.review(rid, "dpo:asha", decision="approved", checklist=ALL)
    assert sent[-1] == ("case_reviewed", {"request_id": rid, "decision": "approved", "sign_off": "approved",
                                          "approvals": 1, "required": 1})
    issues = [m for _, m in production_issues(_cfg(tmp, evidence={"required_approvals": 0}))]
    assert any("required_approvals=0" in m for m in issues)
