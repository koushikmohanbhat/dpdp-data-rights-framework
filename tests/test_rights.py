"""Rights workflow: rules, access, correction, nomination, grievance, erasure via the desk, API, CLI, audit."""
import json
from datetime import timedelta

import pytest
from _db import lineage_url
from fastapi.testclient import TestClient

from dpdp_rights import DataRightsFramework, FrameworkConfig
from dpdp_rights.api.app import create_app
from dpdp_rights.core.models import utcnow
from dpdp_rights.rights import RightsError, RuleError, resolve, versions
from dpdp_rights.security.auth import hash_api_key
from dpdp_rights.security.guardrails import production_issues


def _cfg(tmp, **extra):
    base = {
        "provider": {"type": "echo"},
        "vault": {"local_master_key_path": str(tmp / "m.key")},
        "lineage": {"url": lineage_url(tmp)},
        "purposes": [{"id": "service", "description": "Run the policy"}, {"id": "marketing"},
                     {"id": "kyc", "legal_basis": "legitimate_use", "legal_hold_basis": "Test statute"}],
        "connectors": [{"name": "records", "type": "sql_table",
                        "options": {"url": f"sqlite:///{tmp}/app.db", "table": "records", "content_column": "body",
                                    "principal_column": "principal_id"}}],
        "certificates": {"signer": "local", "local_key_path": str(tmp / "sign.key")},
        "rights": {"recipients": [{"store": "records", "name": "Core platform vendor", "description": "Hosts records"}],
                   "channels": [{"name": "App", "how": "Profile > Privacy"}], "identifiers": ["Policy number"],
                   "contact": "dpo@insurer.example"},
    }
    base.update(extra)
    return FrameworkConfig.from_dict(base)


@pytest.fixture
def fw(workdir):
    tmp, _ = workdir
    return DataRightsFramework(_cfg(tmp))


def _person(f, db, ext="p1", text="mail p1@example.in phone 9876543210"):
    pid = f.principal(ext)
    f.register_identifier(pid, "EMAIL", f"{ext}@example.in")
    f.grant_consent(pid, "service")
    with f.context(pid, purpose="service"):
        s = f.protect(text)
        db.execute("INSERT INTO records VALUES (?,?,?)", (ext, pid, s.text))
        db.commit()
        f.track_artifact("record", "records", {"id": ext}, content=s.text, element_ids=s.element_ids)
    return pid, s


# ---- rules ------------------------------------------------------------------------------------
def test_rules_are_versioned_overridable_within_limits_and_hashed(tmp_path):
    rs, warn = resolve()
    assert rs.id == "dpdp-in" and rs.due_days("grievance") == 30 and not warn
    with pytest.raises(RuleError, match="prescribed limit of 90"):
        resolve(overrides={"grievance": {"respond_within_days": 120}})
    rs2, warn = resolve(overrides={"access": {"respond_within_days": 120}})
    assert warn and rs2.sha256 != rs.sha256 and rs2.overridden == ("access.respond_within_days",)
    with pytest.raises(RuleError, match="cannot override"):
        resolve(overrides={"grievance": {"max_days": 365}})
    # a newer counsel-reviewed version applies to cases received on or after its date
    src = (rs.data | {"version": "2027.06-1", "effective_from": "2027-06-01", "reviewed": "Counsel, memo 7"})
    src["requests"] = {**rs.data["requests"], "grievance": {**rs.data["requests"]["grievance"], "respond_within_days": 15}}
    (tmp_path / "v2.yaml").write_text(json.dumps(src, default=str))
    assert resolve(on="2027-05-31", extra_dir=str(tmp_path))[0].version == "2025.11-3"
    assert resolve(on="2027-06-02", extra_dir=str(tmp_path))[0].due_days("grievance") == 15
    assert [v["version"] for v in versions(extra_dir=str(tmp_path))] == ["2025.11-3", "2027.06-1"]


# ---- access -------------------------------------------------------------------------------------
def test_access_report_reviewed_released_and_revealed_per_setting(fw, workdir):
    _, db = workdir
    pid, _ = _person(fw, db)
    c = fw.rights.submit("access", pid, requested_by="service:app", verified_by="app-login", verification_ref="sess-1")
    assert c["status"] == "in_review" and c["rules"]["rule_set"] == "dpdp-in"
    with pytest.raises(RightsError, match="not released"):
        fw.rights.access_report(c["case_id"])
    with pytest.raises(RightsError, match="submitted"):
        fw.rights.decide(c["case_id"], "service:app", "approve")
    with pytest.raises(RightsError, match="coverage"):
        fw.rights.decide(c["case_id"], "dpo:asha", "approve")          # no inventory: coverage unknown
    fw.rights.decide(c["case_id"], "dpo:asha", "approve", "Checked the call-centre system by hand; nothing further")
    rep = fw.rights.access_report(c["case_id"])
    assert rep["completeness"]["status"] == "coverage_unknown" and rep["completeness"]["reviewer_note"].startswith("Checked")
    types = {d["type"]: d for d in rep["data"]}
    assert {"EMAIL", "PHONE_IN"} <= set(types) and types["PHONE_IN"]["values"][0]["value"].endswith("3210")
    assert "9876543210" not in json.dumps(rep, ensure_ascii=False)                       # masked by default
    assert rep["places"][0]["place"] == "Records in our systems" and rep["purposes"][0]["consent"] == "given"
    assert rep["recipients"] == [{"name": "Core platform vendor", "role": "processor", "description": "Hosts records",
                                  "data_shared": ["Email address", "Mobile number"]}]
    assert fw.rights.access_report(c["case_id"], "full")["data"][1]["values"][0]["value"] == "9876543210"
    assert "values" not in fw.rights.access_report(c["case_id"], "none")["data"][0]
    fw.erase(pid)
    assert all(v["value"] == "[ERASED]" for d in fw.rights.access_report(c["case_id"])["data"] for v in d["values"])


def test_access_report_withholds_exempt_recipients_and_flags_unlisted_processors(workdir):
    tmp, db = workdir
    f = DataRightsFramework(_cfg(tmp, rights={"recipients": [
        {"store": "records", "name": "Enforcement agency", "role": "fiduciary", "exempt_from_access": True,
         "exemption_basis": "s.11(2), notice 12/2027"}]}))
    pid, _ = _person(f, db)
    c = f.rights.submit("access", pid, requested_by="service:app")
    case = f.store.get_rights_case(c["case_id"])
    assert case["outcome"]["review_notes"][0] == "recipient 'Enforcement agency' withheld under s.11(2), notice 12/2027"
    f.rights.decide(c["case_id"], "dpo:asha", "approve", "Checked the call-centre system by hand; nothing further")
    rep = f.rights.access_report(c["case_id"])
    assert rep["recipients"] == [] and "_withheld_recipients" not in rep
    assert "review_notes" not in f.rights.view(c["case_id"], for_principal="self")["outcome"]


# ---- correction ------------------------------------------------------------------------------------
def test_correction_reviewed_then_applied_through_the_vault(fw, workdir):
    _, db = workdir
    pid, s = _person(fw, db)
    c = fw.rights.submit("correction", pid, requested_by="service:app", element_type="EMAIL",
                         new_value="priya.new@example.in", reason="changed my email")
    assert c["status"] == "in_review"
    with pytest.raises(RightsError, match="reason"):
        fw.rights.decide(c["case_id"], "dpo:asha", "reject")
    out = fw.rights.decide(c["case_id"], "dpo:asha", "approve")
    assert out["status"] == "fulfilled" and out["outcome"]["follow_up"][0]["action"].startswith("inform Core platform")
    assert "priya.new@example.in" in fw.vault.reveal(s.text)                      # every copy reads the new value
    assert fw.vault.find_principal_by_identifier("EMAIL", "priya.new@example.in") == pid
    with fw.context(pid, purpose="service"):                                     # old value seen again later
        old = fw.protect("my old address was p1@example.in")
    assert "priya.new@example.in" in fw.vault.reveal(s.text) and "p1@example.in" in fw.vault.reveal(old.text)
    # nothing readable is stored in the case row itself
    row = json.dumps(fw.store.get_rights_case(c["case_id"]), default=str)
    assert "priya.new" not in row and "changed my email" not in row


def test_correction_needs_ref_when_ambiguous_and_complete_adds_a_value(fw, workdir):
    _, db = workdir
    pid, _ = _person(fw, db, text="mail p1@example.in or p1.work@example.in")
    with pytest.raises(RightsError, match="say which one"):
        fw.rights.submit("correction", pid, requested_by="s", element_type="EMAIL", new_value="x@example.in")
    with pytest.raises(RightsError, match="use action=complete"):
        fw.rights.submit("correction", pid, requested_by="s", element_type="PAN", new_value="ABCPR1234K")
    c = fw.rights.submit("correction", pid, requested_by="s", element_type="PAN", action="complete",
                         new_value="ABCPR1234K")
    fw.rights.decide(c["case_id"], "dpo:asha", "approve")
    ref = fw.rights.view(c["case_id"])["outcome"]["ref"]
    assert fw.vault.detokenize(ref) == "ABCPR1234K" and fw.vault.owner_of(ref) == pid


def test_correction_without_review_applies_immediately(workdir):
    tmp, db = workdir
    f = DataRightsFramework(_cfg(tmp, rights={"review_required": []}))
    pid, s = _person(f, db)
    c = f.rights.submit("correction", pid, requested_by="s", element_type="PHONE_IN", new_value="9123456780")
    assert c["status"] == "fulfilled" and "9123456780" in f.vault.reveal(s.text)


# ---- nomination ---------------------------------------------------------------------------------------
def test_nomination_invocation_and_nominee_acting(fw, workdir):
    _, db = workdir
    pid, _ = _person(fw, db)
    n = fw.rights.submit("nomination", pid, requested_by="principal:p1", nominee_name="Sunita Verma",
                         nominee_contact="+91 98111 22334", relationship="spouse", events="both")
    nid = fw.rights.view(n["case_id"])["outcome"]["nomination_id"]
    assert n["status"] == "fulfilled" and fw.rights.nominations(pid)[0]["status"] == "active"
    assert "Sunita" not in json.dumps(fw.store.get_nomination(nid), default=str)          # tokenised
    with pytest.raises(RightsError, match="invoked"):
        fw.rights.submit("access", pid, requested_by="service:cc", on_behalf_of=nid)
    with pytest.raises(RightsError, match="evidence_ref"):
        fw.rights.submit("nominee_invocation", pid, requested_by="service:cc", on_behalf_of=nid, event="death")
    with pytest.raises(RightsError, match="cannot make a nomination"):
        fw.rights.submit("nomination", pid, requested_by="service:cc", on_behalf_of=nid, nominee_name="x",
                         nominee_contact="y")
    inv = fw.rights.submit("nominee_invocation", pid, requested_by="service:cc", on_behalf_of=nid, event="death",
                           evidence_ref="DC-2027-55 verified at branch")
    assert inv["status"] == "in_review"
    fw.rights.decide(inv["case_id"], "dpo:asha", "approve")
    assert fw.rights.nominations(pid)[0]["status"] == "invoked"
    acting = fw.rights.submit("access", pid, requested_by="service:cc", on_behalf_of=nid)
    assert fw.rights.view(acting["case_id"])["on_behalf_of"] == nid


def test_nomination_revoke_blocks_invocation(fw, workdir):
    _, db = workdir
    pid, _ = _person(fw, db)
    n = fw.rights.submit("nomination", pid, requested_by="p", nominee_name="A", nominee_contact="a@x.in",
                         events="incapacity")
    nid = fw.rights.view(n["case_id"])["outcome"]["nomination_id"]
    with pytest.raises(RightsError, match="covers incapacity"):
        fw.rights.submit("nominee_invocation", pid, requested_by="s", on_behalf_of=nid, event="death", evidence_ref="r")
    fw.rights.submit("nomination", pid, requested_by="p", action="revoke", nomination_id=nid)
    with pytest.raises(RightsError, match="revoked"):
        fw.rights.submit("nominee_invocation", pid, requested_by="s", on_behalf_of=nid, event="incapacity",
                         evidence_ref="r")


# ---- grievance -------------------------------------------------------------------------------------------
def test_grievance_acknowledge_resolve_and_escalation_text(fw, workdir):
    _, db = workdir
    pid, _ = _person(fw, db)
    with pytest.raises(RightsError, match="category"):
        fw.rights.submit("grievance", pid, requested_by="p", category="angry", description="x")
    g = fw.rights.submit("grievance", pid, requested_by="principal:p1", category="request_handling",
                         description="My marketing calls continue after I withdrew. Call me on 9876543210.")
    assert g["status"] == "received" and g["due_by"] > utcnow().isoformat()
    with pytest.raises(RightsError, match="raised the grievance"):
        fw.rights.respond(g["case_id"], "principal:p1", "fulfilled", "done")
    fw.rights.respond(g["case_id"], "dpo:asha", "acknowledged", "We are looking into it")
    with pytest.raises(RightsError, match="needs a response"):
        fw.rights.respond(g["case_id"], "dpo:asha", "fulfilled")
    out = fw.rights.respond(g["case_id"], "dpo:asha", "fulfilled", "Removed from the dialler list, ticket MKT-77")
    assert out["status"] == "fulfilled" and "Data Protection Board" in out["outcome"]["board_escalation"]
    assert [e["kind"] for e in out["events"]] == ["received", "acknowledged", "fulfilled"]
    assert out["integrity"]["ok"] and out["integrity"]["signatures_ok"]
    assert "9876543210" not in json.dumps(fw.store.get_rights_case(g["case_id"]), default=str)
    full = fw.rights.view(g["case_id"], reveal="full")
    assert "9876543210" in full["details"]["description"] and "MKT-77" in full["outcome"]["response"]


def test_rights_event_log_tampering_is_detected(fw, workdir):
    _, db = workdir
    pid, _ = _person(fw, db)
    g = fw.rights.submit("grievance", pid, requested_by="p", category="other", description="x")
    fw.rights.respond(g["case_id"], "dpo:asha", "rejected", "Not ours")
    from sqlalchemy import func, update

    from dpdp_rights.lineage.store import rights_event
    with fw.store.engine.begin() as c:
        c.execute(update(rights_event).where(rights_event.c.kind == "rejected")
                  .values(actor=func.replace(rights_event.c.actor, "asha", "ravi")))
    assert fw.rights.verify_chain(g["case_id"])["ok"] is False


# ---- erasure and withdrawal through the desk ---------------------------------------------------------------
def test_erasure_and_withdrawal_cases_mirror_the_erasure_request(fw, workdir):
    _, db = workdir
    pid, _ = _person(fw, db)
    fw.grant_consent(pid, "marketing")
    w = fw.rights.submit("withdrawal", pid, requested_by="service:app", purpose_id="marketing")
    e = fw.rights.submit("erasure", pid, requested_by="service:app", verification_ref="V-9")
    assert w["erasure_request_id"] and e["erasure_request_id"] and w["status"] == "received"
    fw.process_jobs()
    ev = fw.rights.view(e["case_id"])
    assert ev["status"] == "fulfilled" and ev["outcome"]["certificate"] and ev["within_due"] is True
    assert fw.rights.view(w["case_id"])["status"] == "fulfilled"
    with pytest.raises(RightsError, match="purpose_id"):
        fw.rights.submit("withdrawal", pid, requested_by="s")


# ---- SLA, audit pack, guardrails -----------------------------------------------------------------------------
def test_sla_audit_pack_and_guardrails(fw, workdir):
    tmp, db = workdir
    pid, _ = _person(fw, db)
    g = fw.rights.submit("grievance", pid, requested_by="p", category="other", description="x")
    a = fw.rights.submit("access", pid, requested_by="s")
    from sqlalchemy import update

    from dpdp_rights.lineage.store import rights_case
    with fw.store.engine.begin() as c:
        c.execute(update(rights_case).where(rights_case.c.case_id == g["case_id"])
                  .values(due_by=utcnow() - timedelta(days=1)))
    assert fw.rights.sla_counts()["grievance"]["overdue"] == 1
    assert [c["case_id"] for c in fw.rights.list(overdue=True)] == [g["case_id"]]
    fw.rights.decide(a["case_id"], "dpo:asha", "approve", "Checked the call-centre system by hand; nothing further")
    from dpdp_rights.evidence.audit import audit_pack
    rep = audit_pack(fw, utcnow() - timedelta(days=1), utcnow() + timedelta(days=1))
    assert rep["rights"]["by_type"]["access"]["fulfilled"] == 1 and rep["rights"]["overdue_count"] == 1
    assert any(f["code"] == "rights_overdue" and f["request_id"] == g["case_id"] for f in rep["findings"])
    msgs = [m for _, m in production_issues(_cfg(tmp, rights={"overrides": {"grievance": {"respond_within_days": 91}}}))]
    assert any("prescribed limit" in m for m in msgs) and any("rights.recipients is empty" in m for m in msgs)


# ---- API and CLI ---------------------------------------------------------------------------------------------
def test_api_rights_flow_roles_and_public_notice(workdir):
    tmp, db = workdir
    f = DataRightsFramework(_cfg(tmp, api={"auth": {"mode": "api_key", "api_keys": [
        {"name": "app", "sha256": hash_api_key("svc"), "roles": ["service"]},
        {"name": "asha", "sha256": hash_api_key("dpo"), "roles": ["dpo"]},
        {"name": "ravi", "sha256": hash_api_key("rev"), "roles": ["reviewer"]}]}}))
    _person(f, db)
    c = TestClient(create_app(f))
    svc, dpo, rev = ({"x-api-key": k} for k in ("svc", "dpo", "rev"))
    notice = c.get("/v1/rights/notice").json()                   # public, no credentials
    assert notice["grievance_period_days"] == 30 and notice["channels"][0]["name"] == "App" and "gaps" not in notice
    assert "<section" in c.get("/v1/rights/notice?format=html").text
    r = c.post("/v1/rights-requests", headers=svc | {"Idempotency-Key": "a1"},
               json={"type": "access", "external_id": "p1", "verification_ref": "sess-9"}).json()
    again = c.post("/v1/rights-requests", headers=svc | {"Idempotency-Key": "a1"},
                   json={"type": "access", "external_id": "p1", "verification_ref": "sess-9"}).json()
    assert again["duplicate"] and again["case_id"] == r["case_id"]
    cid = r["case_id"]
    assert c.post(f"/v1/rights-requests/{cid}/decision", headers=svc, json={"decision": "approve"}).status_code == 403
    assert c.get(f"/v1/rights-requests/{cid}/access-report", headers=dpo).status_code == 422     # not released
    assert c.post(f"/v1/rights-requests/{cid}/decision", headers=rev, json={"decision": "approve"}).status_code == 422
    assert c.post(f"/v1/rights-requests/{cid}/decision", headers=rev,
                  json={"decision": "approve", "reason": "Checked by hand"}).status_code == 200
    assert c.get(f"/v1/rights-requests/{cid}/access-report", headers=rev).status_code == 403
    assert "Your personal data" in c.get(f"/v1/rights-requests/{cid}/access-report?format=html", headers=dpo).text
    bad = c.post("/v1/rights-requests", headers=svc, json={"type": "grievance", "external_id": "p1", "details": {}})
    assert bad.status_code == 422
    g = c.post("/v1/rights-requests", headers=svc, json={"type": "grievance", "external_id": "p1",
                                                         "details": {"category": "consent", "description": "stop"}}).json()
    assert c.post(f"/v1/rights-requests/{g['case_id']}/response", headers=rev,
                  json={"status": "fulfilled", "response": "ok"}).status_code == 403
    assert c.post(f"/v1/rights-requests/{g['case_id']}/response", headers=dpo,
                  json={"status": "fulfilled", "response": "Stopped, ticket C-1"}).json()["status"] == "fulfilled"
    assert len(c.get("/v1/rights-requests?type=access", headers=rev).json()) == 1
    assert "rights_cases" in c.get("/v1/sla", headers=dpo).json()
    assert c.post("/v1/rights-requests", headers=svc, json={"type": "access", "external_id": "p1",
                                                           "on_behalf_of": "nom_x"}).status_code == 422


def test_cli_rights_commands(workdir, capsys):
    tmp, db = workdir
    import yaml

    from dpdp_rights.cli import main
    (tmp / "c.yaml").write_text(yaml.safe_dump(_cfg(tmp).model_dump(mode="json")))
    f = DataRightsFramework.from_yaml(str(tmp / "c.yaml"))
    _person(f, db)
    cfgp = ["-c", str(tmp / "c.yaml")]
    main(cfgp + ["rights", "notice"])
    assert "We respond to grievances within 30 days" in capsys.readouterr().out
    main(cfgp + ["rights", "rules"])
    assert json.loads(capsys.readouterr().out)["effective"]["version"] == "2025.11-3"
    main(cfgp + ["rights", "submit", "--type", "correction", "--external-id", "p1", "--requested-by", "ops:meena",
                 "--set", "element_type=PHONE_IN", "--set", "new_value=9123456780"])
    cid = json.loads(capsys.readouterr().out)["case_id"]
    main(cfgp + ["rights", "decide", "--case-id", cid, "--actor", "dpo:asha", "--decision", "approve"])
    assert json.loads(capsys.readouterr().out)["status"] == "fulfilled"
    with pytest.raises(SystemExit, match="refused"):
        main(cfgp + ["rights", "decide", "--case-id", cid, "--actor", "dpo:asha", "--decision", "approve"])


def test_local_dev_user_header_allows_separation_of_duties_without_auth(fw, workdir):
    _, db = workdir
    _person(fw, db)
    c = TestClient(create_app(fw))           # api.auth.mode defaults to none (development)
    r = c.post("/v1/rights-requests", headers={"x-dev-user": "meena"},
               json={"type": "access", "external_id": "p1"}).json()
    same = c.post(f"/v1/rights-requests/{r['case_id']}/decision", headers={"x-dev-user": "meena"},
                  json={"decision": "approve"})
    assert same.status_code == 422
    other = c.post(f"/v1/rights-requests/{r['case_id']}/decision", headers={"x-dev-user": "asha"},
                   json={"decision": "approve", "reason": "Checked by hand"})
    assert other.status_code == 200 and other.json()["status"] == "fulfilled"


def test_docs_page_works_offline_and_shows_the_dev_user_field(fw):
    c = TestClient(create_app(fw))
    page = c.get("/docs").text
    assert "/docs-assets/swagger-ui-bundle.js" in page and "cdn.jsdelivr" not in page
    assert c.get("/docs-assets/swagger-ui-bundle.js").status_code == 200
    params = c.get("/openapi.json").json()["paths"]["/v1/rights-requests/{case_id}/decision"]["post"]["parameters"]
    assert "x-dev-user" in [p["name"] for p in params]


# ---- review 18 Nov 2026: idempotency, tokenised references, completeness ---------------------------------
def test_idempotency_keys_are_bound_to_caller_principal_and_request(fw, workdir):
    from dpdp_rights.core.idempotency import IdempotencyConflict
    _, db = workdir
    p1, _ = _person(fw, db, "p1")
    p2, _ = _person(fw, db, "p2", text="mail p2@example.in")
    a = fw.rights.submit("access", p1, requested_by="svc:app", verification_ref="v1", idempotency_key="k1")
    again = fw.rights.submit("access", p1, requested_by="svc:app", verification_ref="v1", idempotency_key="k1")
    assert again["duplicate"] and again["case_id"] == a["case_id"]
    with pytest.raises(IdempotencyConflict) as e:               # another person's request: nothing revealed
        fw.rights.submit("access", p2, requested_by="svc:app", idempotency_key="k1")
    assert a["case_id"] not in str(e.value) and "v1" not in str(e.value)
    with pytest.raises(IdempotencyConflict):                     # same person, different request
        fw.rights.submit("grievance", p1, requested_by="svc:app", idempotency_key="k1", category="other",
                         description="x")
    other = fw.rights.submit("access", p1, requested_by="svc:crm", idempotency_key="k1")   # another caller's key
    assert other["case_id"] != a["case_id"] and not other.get("duplicate")
    assert fw.store.rights_case_by_key("k1") is None             # stored only as a scoped hash


def test_idempotency_compares_the_full_request_including_personal_fields(fw, workdir):
    """Review 18 Nov 2026 (second round): a changed personal field with the same key is a conflict, not a retry."""
    from dpdp_rights.core.idempotency import IdempotencyConflict
    _, db = workdir
    pid, s = _person(fw, db)
    email = next(t for t in s.text.split() if t.startswith("<EMAIL_"))
    cases = [
        ("correction", dict(element_type="EMAIL", ref=email, new_value="new1@example.in"),
         dict(new_value="new2@example.in")),
        ("nomination", dict(nominee_name="Sunita Verma", nominee_contact="9811122233", relationship="sister"),
         dict(nominee_name="Anita Verma")),
        ("nomination", dict(nominee_name="Ravi Rao", nominee_contact="9811122244", relationship="brother"),
         dict(nominee_contact="9811122255")),
        ("grievance", dict(category="other", description="my correction was not applied"),
         dict(description="my access report was late")),
    ]
    for i, (rtype, base, change) in enumerate(cases):
        k = f"full-{i}"
        first = fw.rights.submit(rtype, pid, requested_by="svc", verification_ref="kyc-1", idempotency_key=k, **base)
        exact = fw.rights.submit(rtype, pid, requested_by="svc", verification_ref="kyc-1", idempotency_key=k, **base)
        assert exact["duplicate"] and exact["case_id"] == first["case_id"], rtype
        with pytest.raises(IdempotencyConflict):
            fw.rights.submit(rtype, pid, requested_by="svc", verification_ref="kyc-1", idempotency_key=k,
                             **(base | change))
        with pytest.raises(IdempotencyConflict):                    # a different upstream reference too
            fw.rights.submit(rtype, pid, requested_by="svc", verification_ref="kyc-2", idempotency_key=k, **base)
        stored = fw.store.get_rights_case(first["case_id"])["details"]
        digest = stored["_request_digest"]
        assert len(digest) == 64 and "_request_digest" not in fw.rights.view(first["case_id"])["details"]
        for f in ("new_value", "nominee_name", "nominee_contact", "relationship", "description"):
            if f in base:                                           # no plain personal value kept anywhere
                assert base[f] not in json.dumps(stored, default=str), (rtype, f)


def test_request_digest_is_keyed_not_a_plain_hash(fw):
    import hashlib

    from dpdp_rights.core.idempotency import canonical_request
    c = canonical_request(type="correction", details={"new_value": "9876543210"})
    d = fw.vault.request_digest(c)
    assert d != hashlib.sha256(c).hexdigest()                       # not guessable from the database alone
    assert d == fw.vault.request_digest(canonical_request(details={"new_value": "9876543210", "x": None},
                                                          type="correction"))   # canonical: order, None


def test_erasure_retry_with_different_references_is_a_conflict(fw, workdir):
    from dpdp_rights.core.idempotency import IdempotencyConflict
    _, db = workdir
    pid, _ = _person(fw, db)
    r = fw.submit_request(pid, requested_by="svc", verified_by="kyc", verification_ref="s-1", idempotency_key="e9")
    again = fw.submit_request(pid, requested_by="svc", verified_by="kyc", verification_ref="s-1", idempotency_key="e9")
    assert again["duplicate"] and again["request_id"] == r["request_id"]
    with pytest.raises(IdempotencyConflict):
        fw.submit_request(pid, requested_by="svc", verified_by="kyc", verification_ref="s-2", idempotency_key="e9")
    with pytest.raises(IdempotencyConflict):
        fw.submit_request(pid, requested_by="svc", verified_by="kyc", verification_ref="s-1", idempotency_key="e9",
                          dry_run=True)


def test_concurrent_retry_returns_the_winner_not_an_error(fw, workdir, monkeypatch):
    _, db = workdir
    pid, _ = _person(fw, db)
    first = fw.rights.submit("access", pid, requested_by="svc", idempotency_key="race")
    real = fw.store.rights_case_by_key
    calls = {"n": 0}

    def miss_once(k):                                           # the retry's lookup ran before the first insert
        calls["n"] += 1
        return None if calls["n"] == 1 else real(k)
    monkeypatch.setattr(fw.store, "rights_case_by_key", miss_once)
    again = fw.rights.submit("access", pid, requested_by="svc", idempotency_key="race")
    assert again["duplicate"] and again["case_id"] == first["case_id"]


def test_erasure_key_reuse_for_another_person_is_a_conflict_not_a_silent_duplicate(fw, workdir, monkeypatch):
    from dpdp_rights.core.idempotency import IdempotencyConflict
    _, db = workdir
    p1, _ = _person(fw, db, "p1")
    p2, _ = _person(fw, db, "p2", text="mail p2@example.in")
    r = fw.submit_request(p1, requested_by="svc", idempotency_key="e1")
    assert fw.submit_request(p1, requested_by="svc", idempotency_key="e1")["request_id"] == r["request_id"]
    with pytest.raises(IdempotencyConflict):
        fw.submit_request(p2, requested_by="svc", idempotency_key="e1")
    with pytest.raises(IdempotencyConflict):
        fw.submit_request(p1, requested_by="svc", idempotency_key="e1", withdraw_purpose="service")
    real = fw.store.request_by_idempotency_key
    calls = {"n": 0}

    def miss_once(k):
        calls["n"] += 1
        return None if calls["n"] == 1 else real(k)
    monkeypatch.setattr(fw.store, "request_by_idempotency_key", miss_once)
    assert fw.submit_request(p1, requested_by="svc", idempotency_key="e1")["duplicate"]


def test_api_returns_409_on_key_conflict(workdir):
    tmp, db = workdir
    f = DataRightsFramework(_cfg(tmp))
    _person(f, db, "p1")
    _person(f, db, "p2", text="mail p2@example.in")
    c = TestClient(create_app(f))
    h = {"x-dev-user": "app", "Idempotency-Key": "same"}
    assert c.post("/v1/erasure-requests", headers=h, json={"external_id": "p1"}).status_code == 202
    bad = c.post("/v1/erasure-requests", headers=h, json={"external_id": "p2"})
    assert bad.status_code == 409 and "p1" not in bad.text
    assert c.post("/v1/rights-requests", headers=h, json={"type": "access", "external_id": "p1"}).status_code == 202
    assert c.post("/v1/rights-requests", headers=h, json={"type": "access", "external_id": "p2"}).status_code == 409


def test_nominee_evidence_and_relationship_are_tokenised_and_references_checked(fw, workdir):
    _, db = workdir
    pid, _ = _person(fw, db)
    n = fw.rights.submit("nomination", pid, requested_by="p", nominee_name="Sunita Verma", nominee_contact="s@x.in",
                         relationship="spouse", events="death")
    nid = fw.rights.view(n["case_id"])["outcome"]["nomination_id"]
    inv = fw.rights.submit("nominee_invocation", pid, requested_by="svc:cc", on_behalf_of=nid, event="death",
                           evidence_ref="Death certificate DC-2027-55 for Priya Sharma")
    raw = json.dumps([fw.store.get_rights_case(inv["case_id"]), fw.store.get_rights_case(n["case_id"]),
                      fw.store.get_nomination(nid)], default=str)
    assert "DC-2027-55" not in raw and "Priya" not in raw and "spouse" not in raw
    assert "DC-2027-55" in fw.rights.view(inv["case_id"], reveal="full")["details"]["evidence_ref"]
    with pytest.raises(RightsError, match="verification_ref appears to contain personal data"):
        fw.rights.submit("access", pid, requested_by="svc", verification_ref="called 9876543210")
    with pytest.raises(ValueError, match="personal data"):
        fw.submit_request(pid, requested_by="svc", verification_ref="kyc of p1@example.in")


def _inventory(tmp, systems):
    import yaml
    p = tmp / "inv.yaml"
    p.write_text(yaml.safe_dump({"engagement": {"client": "Acme", "system": "Agent", "prepared_on": "2026-11-01"},
                                 "systems": systems}))
    return str(p)


def test_access_report_states_completeness_prominently(workdir):
    tmp, db = workdir
    from datetime import date
    base = {"name": "Records", "category": "database", "data_elements": ["EMAIL"], "purposes": ["service"],
            "connector": "records", "tested_on": date.today().isoformat()}
    f = DataRightsFramework(_cfg(tmp, rights={"inventory_path": _inventory(tmp, [base])}))
    pid, _ = _person(f, db)
    c = f.rights.submit("access", pid, requested_by="svc")
    f.rights.decide(c["case_id"], "dpo:asha", "approve")          # complete: no note needed
    rep = f.rights.access_report(c["case_id"])
    assert rep["completeness"]["status"] == "complete" and rep["completeness"]["searched"] == ["Records"]
    from dpdp_rights.rights.access import access_html
    assert "Completeness: Complete" in access_html(rep)

    manual = {"name": "Call recordings", "category": "saas", "data_elements": ["PHONE_IN"], "purposes": ["service"],
              "manual_procedure": "CC-07", "tested_on": date.today().isoformat()}
    gap = {"name": "Old CRM", "category": "database", "data_elements": ["EMAIL"], "purposes": ["service"]}
    f2 = DataRightsFramework(_cfg(tmp, lineage={"url": f"sqlite:///{tmp}/l2.db"},
                                  rights={"inventory_path": _inventory(tmp, [base, manual, gap])}))
    pid2, _ = _person(f2, db, "p9", text="mail p9@example.in")
    c2 = f2.rights.submit("access", pid2, requested_by="svc")
    notes = f2.store.get_rights_case(c2["case_id"])["outcome"]["review_notes"]
    assert any("Call recordings" in n for n in notes) and any("Old CRM" in n for n in notes)
    with pytest.raises(RightsError, match="partial"):
        f2.rights.decide(c2["case_id"], "dpo:asha", "approve")
    f2.rights.decide(c2["case_id"], "dpo:asha", "approve", "Call recordings searched under CC-07: none found")
    rep2 = f2.rights.access_report(c2["case_id"])
    comp = rep2["completeness"]
    assert comp["status"] == "partial" and comp["checked_by_hand"] == ["Call recordings"]
    assert comp["not_searched"] == ["Old CRM"] and "none found" in comp["reviewer_note"]
    page = access_html(rep2)
    assert page.index("Completeness: Partial") < page.index("What we hold")       # before the data, not after
    assert "Old CRM" in page and "none found" in page


def test_inventory_path_resolves_relative_to_the_config_file(tmp_path):
    import yaml

    from dpdp_rights import FrameworkConfig
    (tmp_path / "cfg").mkdir()
    (tmp_path / "cfg" / "dpdp.yaml").write_text(yaml.safe_dump({"rights": {"inventory_path": "../inv/inventory.yaml"}}))
    cfg = FrameworkConfig.load(str(tmp_path / "cfg" / "dpdp.yaml"))
    assert cfg.rights.inventory_path == str((tmp_path / "inv" / "inventory.yaml").resolve())


# ---- review 18 Nov 2026 (third round): completeness rests on a search for this request ---------------------
def _complete_setup(tmp, db, tested_on=None, rights=None, name="c1"):
    from datetime import date
    sysrow = {"name": "Records", "category": "database", "data_elements": ["EMAIL"], "purposes": ["service"],
              "connector": "records", "tested_on": tested_on or date.today().isoformat()}
    f = DataRightsFramework(_cfg(tmp, lineage={"url": f"sqlite:///{tmp}/{name}.db"},
                                 rights={"inventory_path": _inventory(tmp, [sysrow])} | (rights or {})))
    pid, _ = _person(f, db, name, text=f"mail {name}@example.in")
    return f, pid


def test_complete_needs_a_successful_search_for_this_request(workdir, monkeypatch):
    tmp, db = workdir
    f, pid = _complete_setup(tmp, db)
    calls = []
    real = f.connectors["records"].discover
    monkeypatch.setattr(f.connectors["records"], "discover", lambda ctx: calls.append(ctx.principal_id) or real(ctx))
    c = f.rights.submit("access", pid, requested_by="svc")
    comp = f.store.get_rights_case(c["case_id"])["outcome"]["report"]["completeness"]
    assert calls == [pid] and comp["status"] == "complete" and comp["search_ran"] and comp["searched"] == ["Records"]

    def boom(ctx):
        raise RuntimeError("store unreachable")
    monkeypatch.setattr(f.connectors["records"], "discover", boom)
    c2 = f.rights.submit("access", pid, requested_by="svc")
    case = f.store.get_rights_case(c2["case_id"])
    comp2 = case["outcome"]["report"]["completeness"]
    assert comp2["status"] == "partial" and comp2["search_failed"] == ["Records"] and not comp2["searched"]
    assert any("search failed" in n for n in case["outcome"]["review_notes"])
    with pytest.raises(RightsError, match="partial"):
        f.rights.decide(c2["case_id"], "dpo:asha", "approve")


def test_untested_or_stale_systems_are_not_complete(workdir):
    from datetime import date, timedelta
    tmp, db = workdir
    old = (date.today() - timedelta(days=400)).isoformat()
    f, pid = _complete_setup(tmp, db, tested_on=old, name="c2")
    c = f.rights.submit("access", pid, requested_by="svc")
    comp = f.store.get_rights_case(c["case_id"])["outcome"]["report"]["completeness"]
    assert comp["status"] == "partial" and comp["not_tested"] == ["Records"] and comp["searched"] == ["Records"]
    f.rights.decide(c["case_id"], "dpo:asha", "approve", "retest booked; search ran clean")
    from dpdp_rights.rights.access import access_html
    page = access_html(f.rights.access_report(c["case_id"]))
    assert "Not tested recently" in page and "Searched for this request: 1 of 1" in page


def test_search_off_gives_configured_coverage_never_complete(workdir, monkeypatch):
    tmp, db = workdir
    f, pid = _complete_setup(tmp, db, rights={"access_search": False}, name="c3")
    monkeypatch.setattr(f.orchestrator, "search", lambda ctx: pytest.fail("search must not run"))
    c = f.rights.submit("access", pid, requested_by="svc")
    comp = f.store.get_rights_case(c["case_id"])["outcome"]["report"]["completeness"]
    assert comp["status"] == "configured_coverage" and comp["configured_only"] == ["Records"]
    assert not comp["search_ran"] and not comp["searched"]
    with pytest.raises(RightsError):                       # still needs a reviewer note to release
        f.rights.decide(c["case_id"], "dpo:asha", "approve")
    f.rights.decide(c["case_id"], "dpo:asha", "approve", "configured coverage accepted by DPO")
    from dpdp_rights.rights.access import access_html
    assert "Configured coverage" in access_html(f.rights.access_report(c["case_id"]))


def test_lineage_only_connectors_are_reported_from_records(workdir, monkeypatch):
    tmp, db = workdir
    f, pid = _complete_setup(tmp, db, name="c4")
    from dpdp_rights.delivery import inventory as invmod
    real = invmod.load_matrix
    monkeypatch.setattr(invmod, "load_matrix", lambda: {k: (v | {"discover": "lineage"} if k == "sql_table" else v)
                                                        for k, v in real().items()})
    comp = f.store.get_rights_case(f.rights.submit("access", pid, requested_by="svc")["case_id"])["outcome"][
        "report"]["completeness"]
    assert comp["status"] == "partial" and comp["from_records"] == ["Records"]


def test_access_search_finds_untracked_copies(workdir):
    tmp, db = workdir
    f, pid = _complete_setup(tmp, db, name="c5")
    tok = f.vault.tokens_for(pid)[0]
    db.execute("INSERT INTO records VALUES (?,?,?)", ("untracked", pid, f"copy {tok}"))
    db.commit()
    before = len(f.store.downstream(pid))
    c = f.rights.submit("access", pid, requested_by="svc")
    assert len(f.store.downstream(pid)) == before + 1          # found by this request's search, now in lineage
    places = f.store.get_rights_case(c["case_id"])["outcome"]["report"]["places"]
    assert sum(p["items"] for p in places) == before + 1


# ---- review 18 Nov 2026 (fourth round): completeness combinations, judged directly ----------------------------
TODAY = __import__("datetime").date(2026, 11, 18)


def _days_ago(n):
    from datetime import timedelta
    return None if n is None else (TODAY - timedelta(days=n)).isoformat()


def _completeness_fw(tmp, systems):
    conns = [{"name": n, "type": "sql_table",
              "options": {"url": f"sqlite:///{tmp}/app.db", "table": "records", "content_column": "body",
                          "principal_column": "principal_id"}} for n in ("records", "logs")]
    return DataRightsFramework(_cfg(tmp, connectors=conns, lineage={"url": f"sqlite:///{tmp}/combo.db"},
                                    rights={"inventory_path": _inventory(tmp, systems)}))


def _auto(name, conn, tested):
    return {"name": name, "category": "database", "data_elements": ["EMAIL"], "purposes": ["service"],
            "connector": conn, "tested_on": tested}


OK = {"ok": True, "found": 1, "new": 0, "error": None}
FAIL = {"ok": False, "found": 0, "new": 0, "error": "RuntimeError"}
LISTS = ("searched", "search_failed", "from_records", "not_tested", "checked_by_hand", "not_searched")


@pytest.mark.parametrize("tested,search,unconfirmed,status,expect", [
    # search succeeded; the inventory test decides
    (0, {"records": OK}, [], "complete", {"searched"}),
    (180, {"records": OK}, [], "complete", {"searched"}),                       # boundary: still within window
    (181, {"records": OK}, [], "partial", {"searched", "not_tested"}),          # stale test, search fine
    (None, {"records": OK}, [], "partial", {"searched", "not_tested"}),         # never tested, search fine
    (-3, {"records": OK}, [], "partial", {"searched", "not_tested"}),           # tested_on in the future
    (0, {"records": OK}, ["records"], "partial", {"searched"}),                 # recipients unconfirmed
    # search failed or never ran for this connector
    (0, {"records": FAIL}, [], "partial", {"search_failed"}),
    (400, {"records": FAIL}, [], "partial", {"search_failed", "not_tested"}),   # failed and stale
    (0, {}, [], "partial", {"search_failed"}),                                  # connector absent from the run
    # no search for the request
    (0, None, [], "configured_coverage", set()),
    (400, None, [], "partial", {"not_tested"}),                                 # configured but stale: not even that
    (None, None, [], "partial", {"not_tested"}),
])
def test_completeness_combinations_for_one_automated_system(workdir, tested, search, unconfirmed, status, expect):
    from dpdp_rights.rights.access import completeness
    tmp, _ = workdir
    f = _completeness_fw(tmp, [_auto("Records", "records", _days_ago(tested))])
    out, notes = completeness(f, unconfirmed, search, today=TODAY)
    assert out["status"] == status
    assert {k for k in LISTS if out[k]} == expect, out
    assert out["unconfirmed_recipients"] == len(unconfirmed) and out["search_ran"] == (search is not None)
    if "not_tested" in expect:
        assert any("not tested end to end" in n for n in notes)
    if search is None:
        assert out["configured_only"] == ["Records"]


@pytest.mark.parametrize("tested,expect", [(0, {"checked_by_hand"}), (400, {"checked_by_hand", "not_tested"}),
                                           (None, {"checked_by_hand", "not_tested"})])
def test_manual_systems_are_never_complete_and_report_stale_tests(workdir, tested, expect):
    from dpdp_rights.rights.access import completeness
    tmp, _ = workdir
    manual = {"name": "Call recordings", "category": "saas", "data_elements": ["PHONE_IN"], "purposes": ["service"],
              "manual_procedure": "CC-07", "tested_on": _days_ago(tested)}
    f = _completeness_fw(tmp, [_auto("Records", "records", _days_ago(0)), manual])
    out, _ = completeness(f, [], {"records": OK}, today=TODAY)
    assert out["status"] == "partial" and {k for k in LISTS if out[k]} == {"searched"} | expect
    assert out["checked_by_hand"] == ["Call recordings"]


def test_mixed_inventory_puts_each_system_in_the_right_lists(workdir, monkeypatch):
    from dpdp_rights.delivery import inventory as invmod
    from dpdp_rights.rights.access import _banner, completeness
    tmp, _ = workdir
    real = invmod.load_matrix
    systems = [
        _auto("Policy DB", "records", _days_ago(10)),                           # searched, tested
        _auto("App logs", "logs", _days_ago(300)),                              # searched, stale test
        {"name": "Call recordings", "category": "saas", "data_elements": ["PHONE_IN"], "purposes": ["service"],
         "manual_procedure": "CC-07", "tested_on": _days_ago(5)},
        {"name": "Email platform", "category": "saas", "data_elements": ["EMAIL"], "purposes": ["service"]},
    ]
    f = _completeness_fw(tmp, systems)
    out, notes = completeness(f, [], {"records": OK, "logs": OK}, today=TODAY)
    assert out["status"] == "partial"
    assert sorted(out["searched"]) == ["App logs", "Policy DB"] and out["not_tested"] == ["App logs"]
    assert out["checked_by_hand"] == ["Call recordings"] and out["not_searched"] == ["Email platform"]
    assert not out["search_failed"] and not out["from_records"] and out["basis"]["systems"] == 4
    # the same inventory, with the log store's search failing and its connector only able to act on records
    monkeypatch.setattr(invmod, "load_matrix", lambda: real())
    out2, _ = completeness(f, [], {"records": OK, "logs": FAIL}, today=TODAY)
    assert out2["search_failed"] == ["App logs"] and out2["searched"] == ["Policy DB"]
    monkeypatch.setattr(invmod, "load_matrix", lambda: {k: (v | {"discover": "lineage"}) if k == "sql_table"
                                                        else v for k, v in real().items()})
    out3, _ = completeness(f, [], {"records": OK, "logs": OK}, today=TODAY)
    assert sorted(out3["from_records"]) == ["App logs", "Policy DB"] and not out3["searched"]
    assert out3["not_tested"] == ["App logs"]                                    # staleness still reported
    page = _banner(out | {"summary": "x"})
    for text in ("Partial", "<b>Not tested recently:</b> App logs", "Call recordings",
                 "<b>Not searched:</b> Email platform",
                 "Searched for this request: 2 of 4"):
        assert text in page, text


def test_future_tested_on_is_an_inventory_error(workdir):
    from datetime import timedelta

    from dpdp_rights.delivery.inventory import Inventory, coverage_report
    tmp, _ = workdir
    f = _completeness_fw(tmp, [_auto("Records", "records", (TODAY + timedelta(days=5)).isoformat())])
    rep = coverage_report(Inventory.load(f.config.rights.inventory_path), f.config, today=TODAY)
    assert rep["systems"][0]["tested"] is False
    assert any(x["level"] == "error" and "in the future" in x["message"] for x in rep["findings"])
