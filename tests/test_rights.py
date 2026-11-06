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
    assert resolve(on="2027-05-31", extra_dir=str(tmp_path))[0].version == "2025.11-1"
    assert resolve(on="2027-06-02", extra_dir=str(tmp_path))[0].due_days("grievance") == 15
    assert [v["version"] for v in versions(extra_dir=str(tmp_path))] == ["2025.11-1", "2027.06-1"]


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
    fw.rights.decide(c["case_id"], "dpo:asha", "approve")
    rep = fw.rights.access_report(c["case_id"])
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
    assert case["outcome"]["review_notes"] == ["recipient 'Enforcement agency' withheld under s.11(2), notice 12/2027"]
    f.rights.decide(c["case_id"], "dpo:asha", "approve")
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
    fw.rights.decide(a["case_id"], "dpo:asha", "approve")
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
                   json={"type": "access", "external_id": "p1"}).json()
    assert again["duplicate"] and again["case_id"] == r["case_id"]
    cid = r["case_id"]
    assert c.post(f"/v1/rights-requests/{cid}/decision", headers=svc, json={"decision": "approve"}).status_code == 403
    assert c.get(f"/v1/rights-requests/{cid}/access-report", headers=dpo).status_code == 422     # not released
    assert c.post(f"/v1/rights-requests/{cid}/decision", headers=rev, json={"decision": "approve"}).status_code == 200
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
    assert json.loads(capsys.readouterr().out)["effective"]["version"] == "2025.11-1"
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
                   json={"decision": "approve"})
    assert other.status_code == 200 and other.json()["status"] == "fulfilled"


def test_docs_page_works_offline_and_shows_the_dev_user_field(fw):
    c = TestClient(create_app(fw))
    page = c.get("/docs").text
    assert "/docs-assets/swagger-ui-bundle.js" in page and "cdn.jsdelivr" not in page
    assert c.get("/docs-assets/swagger-ui-bundle.js").status_code == 200
    params = c.get("/openapi.json").json()["paths"]["/v1/rights-requests/{case_id}/decision"]["post"]["parameters"]
    assert "x-dev-user" in [p["name"] for p in params]
