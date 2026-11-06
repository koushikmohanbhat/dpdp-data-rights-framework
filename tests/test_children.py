"""Children and wards: verifiable consent of a parent or lawful guardian (Act s.9; Rules r.10-12): docs/children.md."""
import json

import pytest
from fastapi.testclient import TestClient
from test_consent_managers import SECRET, _body, _cm, _event, _signed
from test_rights import _cfg

from dpdp_rights import DataRightsFramework
from dpdp_rights.api.app import create_app
from dpdp_rights.consent.children import ChildrenError
from dpdp_rights.consent.ledger import ChildProcessingRestricted, ConsentDenied, ParentalConsentRequired
from dpdp_rights.security.auth import hash_api_key
from dpdp_rights.security.guardrails import production_issues

PURPOSES = [{"id": "service"}, {"id": "marketing"},
            {"id": "ads", "child_restricted": True},
            {"id": "school_safety", "child_restricted": True, "child_exemption": "part_a.educational_institution"},
            {"id": "email_account", "child_exemption": "part_b.email_account"},
            {"id": "kyc", "legal_basis": "legitimate_use", "legal_hold_basis": "Test statute"}]


def _kids_cfg(tmp, **children):
    return _cfg(tmp, purposes=PURPOSES, children={"enabled": True, "token_issuers": ["digilocker"], **children})


@pytest.fixture
def kf(workdir):
    tmp, _ = workdir
    return DataRightsFramework(_kids_cfg(tmp))


def _child(f, ext="kid-1"):
    pid = f.principal(ext)
    f.children.set_status(pid, "child", basis="declared_then_verified", set_by="onboarding", verification_ref="onb-1")
    return pid


def _parent(f, child, ext="parent-1", **kw):
    kw = {"method": "virtual_token", "issuer": "digilocker", "verification_ref": "dl-txn-123",
          "verified_by": "kyc-service", "relationship": "mother"} | kw
    return f.children.record_guardian(child, f.principal(ext), **kw)


def _run(f, pid, purpose):
    with f.context(pid, purpose=purpose):
        return f.protect("hello from the app")


# ---- status ------------------------------------------------------------------------------------------------------
def test_off_by_default_nothing_changes(workdir):
    tmp, _ = workdir
    f = DataRightsFramework(_cfg(tmp))
    pid = f.principal("x")
    f.grant_consent(pid, "service")
    _run(f, pid, "service")
    assert f.children.status(pid)["enforced"] is False


def test_unknown_status_blocks_consent_based_processing_until_set(kf):
    pid = kf.principal("u")
    kf.grant_consent(pid, "service")
    with pytest.raises(ConsentDenied, match="age_status_unknown"):
        _run(kf, pid, "service")
    _run(kf, pid, "kyc")                                  # legitimate use still runs
    kf.children.set_status(pid, "adult", basis="verified", set_by="kyc", verification_ref="kyc-9")
    _run(kf, pid, "service")


def test_unknown_status_adult_treats_people_as_adults(workdir):
    tmp, _ = workdir
    f = DataRightsFramework(_kids_cfg(tmp, unknown_status="adult"))
    pid = f.principal("u")
    f.grant_consent(pid, "service")
    _run(f, pid, "service")


# ---- verifiable parental consent ----------------------------------------------------------------------------------
def test_a_childs_consent_must_come_from_a_verified_parent(kf):
    kid = _child(kf)
    with pytest.raises(ParentalConsentRequired, match="must be given by a parent"):
        kf.grant_consent(kid, "service")
    g = _parent(kf, kid)
    assert g["method"] == "virtual_token" and g["issuer"] == "digilocker" and g["status"] == "active"
    assert g["relationship"].startswith("<RIGHTS_NOTE_")                 # stored as a vault token
    assert kf.children.status(g["guardian_principal_id"])["status"] == "adult"
    kf.grant_consent(kid, "service", guardian_id=g["guardian_id"], actor="parent-app")
    _run(kf, kid, "service")
    kinds = [e["kind"] for e in kf.consent_history.events(kid)]
    assert kinds == ["status_set", "guardian_verified", "given"]
    assert kf.consent_history.events(kid)[-1]["body"]["guardian_id"] == g["guardian_id"]
    assert kf.consent_history.verify(kid)["ok"]


def test_consent_given_before_the_child_was_identified_does_not_count(kf):
    pid = kf.principal("kid")
    kf.grant_consent(pid, "service")                   # recorded while the status was unknown
    kf.children.set_status(pid, "child", basis="verified", set_by="onboarding")
    with pytest.raises(ParentalConsentRequired):
        _run(kf, pid, "service")


def test_revoking_the_guardian_stops_processing_on_their_consent(kf):
    kid = _child(kf)
    g = _parent(kf, kid)
    kf.grant_consent(kid, "service", guardian_id=g["guardian_id"])
    kf.children.revoke_guardian(g["guardian_id"], reason="parent asked, ticket T-9", actor="dpo")
    with pytest.raises(ParentalConsentRequired):
        _run(kf, kid, "service")
    with pytest.raises(ParentalConsentRequired, match="revoked"):
        kf.grant_consent(kid, "service", guardian_id=g["guardian_id"])
    with pytest.raises(ChildrenError, match="already revoked"):
        kf.children.revoke_guardian(g["guardian_id"], reason="again", actor="dpo")
    assert kf.consent_history.events(kid)[-1]["kind"] == "guardian_revoked"


def test_a_guardian_of_one_child_cannot_consent_for_another(kf):
    a, b = _child(kf, "a"), _child(kf, "b")
    g = _parent(kf, a)
    with pytest.raises(ChildrenError, match="does not belong"):
        kf.grant_consent(b, "service", guardian_id=g["guardian_id"])


def test_withdrawal_by_the_parent_erases_and_stops_processing(kf):
    kid = _child(kf)
    g = _parent(kf, kid)
    kf.grant_consent(kid, "service", guardian_id=g["guardian_id"])
    kf.withdraw_consent(kid, "service", actor="parent-app")
    with pytest.raises(ParentalConsentRequired):
        _run(kf, kid, "service")


# ---- s.9(3) and the Fourth Schedule ---------------------------------------------------------------------------------
def test_tracking_and_targeted_ads_are_refused_for_children_even_with_parental_consent(kf):
    kid = _child(kf)
    g = _parent(kf, kid)
    with pytest.raises(ChildProcessingRestricted, match=r"s\.9\(3\)"):
        kf.grant_consent(kid, "ads", guardian_id=g["guardian_id"])
    with pytest.raises(ChildProcessingRestricted):
        _run(kf, kid, "ads")
    adult = kf.principal("grown-up")
    kf.children.set_status(adult, "adult", basis="verified", set_by="kyc")
    kf.grant_consent(adult, "ads")
    _run(kf, adult, "ads")                              # adults are not affected


def test_exempt_purposes_run_without_parental_consent(kf):
    kid = _child(kf)
    assert _run(kf, kid, "school_safety") is not None   # exempt from s.9(1) and s.9(3) (Part A, educational)
    _run(kf, kid, "email_account")
    with kf.context(kid, purpose="email_account"):
        kf.protect("hi")


def test_exemptions_must_exist_in_the_rule_set(workdir):
    tmp, _ = workdir
    cfg = _cfg(tmp, purposes=[{"id": "x", "child_exemption": "part_z.anything"}], children={"enabled": True})
    with pytest.raises(ChildrenError, match="not in the rule set"):
        DataRightsFramework(cfg)


def test_rule_set_lists_rule_10_methods_rule_11_authorities_and_fourth_schedule(kf):
    ch = kf.children.rules
    assert ch["age_of_majority"] == 18 and str(ch["commencement"]) == "2027-05-13"
    assert set(ch["parent_methods"]) == {"fiduciary_records", "voluntary_details", "virtual_token"}
    assert set(ch["guardian_methods"]) == {"court", "designated_authority", "local_level_committee"}
    assert len(ch["exemptions"]) == 11 and all(e["condition"] for e in ch["exemptions"].values())


# ---- wards (persons with disability with a lawful guardian) -------------------------------------------------------
def test_a_wards_guardian_must_be_appointed_under_rule_11(kf):
    ward = kf.principal("w")
    kf.children.set_status(ward, "ward", basis="guardianship order on file", set_by="ops")
    with pytest.raises(ChildrenError, match="Rule 11"):
        _parent(kf, ward)                               # a virtual token is not a guardianship appointment
    g = _parent(kf, ward, method="court", issuer="District Court, Pune", verification_ref="order-2026-441")
    kf.grant_consent(ward, "service", guardian_id=g["guardian_id"])
    _run(kf, ward, "service")


# ---- what a guardian record must carry -----------------------------------------------------------------------------
@pytest.mark.parametrize("kw,msg", [
    ({"method": "court"}, "Rule 10"),
    ({"issuer": None}, "needs the issuer"),
    ({"issuer": "some-app"}, "not in children.token_issuers"),
    ({"verification_ref": ""}, "verification_ref is required"),
    ({"verification_ref": "mother is priya@example.in"}, "personal data"),
])
def test_guardian_records_are_validated(kf, kw, msg):
    kid = _child(kf)
    with pytest.raises(ChildrenError, match=msg):
        _parent(kf, kid, **kw)


def test_a_guardian_must_be_an_adult_and_someone_else(kf):
    kid, other_kid = _child(kf, "k1"), _child(kf, "k2")
    with pytest.raises(ChildrenError, match="must be an adult"):
        kf.children.record_guardian(kid, other_kid, method="fiduciary_records", verification_ref="r1",
                                    verified_by="kyc")
    with pytest.raises(ChildrenError, match="own guardian"):
        kf.children.record_guardian(kid, kid, method="fiduciary_records", verification_ref="r1", verified_by="kyc")
    adult = kf.principal("a")
    with pytest.raises(ChildrenError, match="before recording a guardian"):
        kf.children.record_guardian(adult, kid, method="fiduciary_records", verification_ref="r1", verified_by="kyc")


def test_status_values_and_references_are_checked(kf):
    pid = kf.principal("p")
    with pytest.raises(ChildrenError, match="status must be"):
        kf.children.set_status(pid, "teen", basis="declared", set_by="x")
    with pytest.raises(ChildrenError, match="personal data"):
        kf.children.set_status(pid, "child", basis="declared", set_by="x", verification_ref="call 9876543210")


# ---- through a Consent Manager -----------------------------------------------------------------------------------------
def test_a_consent_manager_grant_for_a_child_needs_a_verified_guardian(workdir, monkeypatch):
    monkeypatch.setenv("CM_SECRET", SECRET)
    tmp, _ = workdir
    f = DataRightsFramework(_cfg(tmp, purposes=PURPOSES, children={"enabled": True, "token_issuers": ["digilocker"]},
                                 consent_managers=[_cm(purpose_map={"SVC": "service"})]))
    kid = _child(f, "cust-1")

    def send(ev):
        b = _body(ev)
        return f.consent_managers.receive("sahmati", _signed(b), b)["results"][0]

    r = send(_event("given", "g-1", purposes=["SVC"]))
    assert r["outcome"] == "refused" and "must be given by a parent" in r["reason"]
    g = _parent(f, kid)
    r = send(_event("given", "g-2", artefact="a2", purposes=["SVC"], guardian_id=g["guardian_id"]))
    assert r["outcome"] == "applied"
    _run(f, kid, "service")


# ---- configuration, API, CLI ------------------------------------------------------------------------------------------
def test_production_check_flags_rules_that_are_not_enforced(workdir):
    tmp, _ = workdir
    off = [m for _, m in production_issues(_cfg(tmp, purposes=PURPOSES))]
    assert any("children.enabled is off" in m for m in off)
    adult = [m for _, m in production_issues(_kids_cfg(tmp, unknown_status="adult"))]
    assert any("unknown_status=adult" in m for m in adult)


def test_api_records_status_and_guardian_and_takes_consent_from_them(workdir):
    tmp, _ = workdir
    keys = {"dpo": ["dpo"], "app": ["service"]}
    cfg = _kids_cfg(tmp, ).model_copy(update={"api": _cfg(tmp, api={"auth": {"mode": "api_key", "api_keys": [
        {"name": n, "sha256": hash_api_key(f"k-{n}"), "roles": r} for n, r in keys.items()]}}).api})
    c = TestClient(create_app(config=cfg))
    app = {"X-API-Key": "k-app"}
    assert c.post("/v1/children/status", json={"external_id": "kid", "status": "child", "basis": "verified"},
                  headers=app).json()["status"] == "child"
    assert c.post("/v1/consents", json={"external_id": "kid", "purpose_id": "service"}, headers=app).status_code == 403
    g = c.post("/v1/children/guardians", json={"external_id": "kid", "guardian_external_id": "mum", "method":
               "virtual_token", "issuer": "digilocker", "verification_ref": "dl-1"}, headers=app)
    assert g.status_code == 201 and g.json()["verified_by"] == "api_key:app"
    gid = g.json()["guardian_id"]
    assert c.post("/v1/consents", json={"external_id": "kid", "purpose_id": "service", "guardian_id": gid},
                  headers=app).status_code == 200
    bad = c.post("/v1/children/guardians", json={"external_id": "kid", "guardian_external_id": "mum",
                                                 "method": "court", "verification_ref": "x"}, headers=app)
    assert bad.status_code == 422
    view = c.get("/v1/children/kid", headers={"X-API-Key": "k-dpo"}).json()
    assert view["status"] == "child" and view["guardians"][0]["guardian_id"] == gid
    assert c.get("/v1/children/kid", headers=app).status_code == 403
    assert c.post(f"/v1/children/guardians/{gid}/revoke", json={"reason": "ticket T-1"},
                  headers=app).json()["status"] == "revoked"
    assert c.get("/v1/children/nobody", headers={"X-API-Key": "k-dpo"}).status_code == 404


def test_cli_children_commands(workdir, capsys):
    import yaml

    from dpdp_rights.cli import main

    tmp, _ = workdir
    (tmp / "c.yaml").write_text(yaml.safe_dump(_kids_cfg(tmp).model_dump()))
    base = ["-c", str(tmp / "c.yaml"), "children"]
    main(base + ["status", "--external-id", "kid", "--status", "child", "--basis", "verified", "--by", "ops"])
    assert json.loads(capsys.readouterr().out)["status"] == "child"
    main(base + ["guardian", "--external-id", "kid", "--guardian-external-id", "mum", "--method", "virtual_token",
                 "--issuer", "digilocker", "--ref", "dl-9", "--by", "ops"])
    gid = json.loads(capsys.readouterr().out)["guardian_id"]
    main(base + ["show", "--external-id", "kid"])
    assert json.loads(capsys.readouterr().out)["guardians"][0]["guardian_id"] == gid
    with pytest.raises(SystemExit, match="refused"):
        main(base + ["guardian", "--external-id", "kid", "--guardian-external-id", "mum", "--method", "court",
                     "--ref", "x", "--by", "ops"])
