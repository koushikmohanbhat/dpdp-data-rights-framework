from fastapi.testclient import TestClient

from dpdp_rights.api.app import create_app


def test_api_consent_and_dry_run(dpdp, workdir):
    tmp, db = workdir
    c = TestClient(create_app(dpdp))
    r = c.post("/v1/consents", json={"external_id": "api-1", "purpose_id": "service"})
    pid = r.json()["principal_id"]
    with dpdp.context(pid, purpose="service"):
        safe = dpdp.protect("mail api@x.in")
        db.execute("INSERT INTO records VALUES ('a', ?, ?)", (pid, safe.text))
        db.commit()
        dpdp.track_artifact("record", "records", {"id": "a"}, content=safe.text, element_ids=safe.element_ids)
    r = c.post("/v1/erasure-requests", json={"external_id": "api-1", "dry_run": True})
    assert r.status_code == 202
    rid = r.json()["request_id"]
    s = c.get(f"/v1/erasure-requests/{rid}").json()
    assert s["request"]["status"] == "planned" and s["actions"][0]["action"] == "delete"
    assert c.get(f"/v1/principals/{pid}/lineage").json()[0]["store"] == "records"
    assert c.post("/v1/erasure-requests", json={"external_id": "nobody"}).status_code == 404
