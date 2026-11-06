"""DPO console: static, strict headers, data only through the role-checked API (docs/console.md)."""
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from test_rights import _cfg

from dpdp_rights import DataRightsFramework
from dpdp_rights.api.app import create_app
from dpdp_rights.security.auth import hash_api_key

STATIC = Path(__file__).parents[1] / "src" / "dpdp_rights" / "console"
KEYS = {"dpo": ["dpo"], "rev": ["reviewer"], "app": ["service"]}


def _client(tmp, **api):
    cfg = _cfg(tmp, api={"auth": {"mode": "api_key", "api_keys": [
        {"name": n, "sha256": hash_api_key(f"k-{n}"), "roles": r} for n, r in KEYS.items()]}, **api})
    f = DataRightsFramework(cfg)
    return TestClient(create_app(dpdp=f, config=cfg)), f


def _h(who):
    return {"X-API-Key": f"k-{who}"}


def test_console_is_served_with_strict_headers_and_no_auth_needed_for_the_static_files(workdir):
    c, _ = _client(workdir[0])
    r = c.get("/console", follow_redirects=False)
    assert r.status_code == 307 and r.headers["location"] == "/console/"
    page = c.get("/console/")
    assert page.status_code == 200 and "DPO console" in page.text
    csp = page.headers["content-security-policy"]
    assert "script-src 'self'" in csp and "frame-ancestors 'none'" in csp and "unsafe-inline" not in csp
    assert page.headers["x-frame-options"] == "DENY" and page.headers["cache-control"] == "no-store"
    assert c.get("/console/app.js").headers["content-type"].startswith("text/javascript")
    assert "content-security-policy" not in c.get("/healthz").headers      # only the console gets them


def test_console_can_be_switched_off(workdir):
    c, _ = _client(workdir[0], console=False)
    assert c.get("/console/").status_code == 404


def test_console_code_never_inserts_data_as_html_or_loads_anything_external():
    js = (STATIC / "app.js").read_text()
    html = (STATIC / "index.html").read_text()
    assert not re.search(r"innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(|new Function", js)
    assert "localStorage" not in js                                           # credentials: this tab only
    assert not re.search(r"https?://(?!www\.w3\.org/2000/svg)", js + html)     # no CDNs or third parties
    assert "<script>" not in html and "style=" not in html + js                # CSP: no inline script or style


def test_erasure_queue_lists_requests_with_sign_off_state(workdir):
    c, f = _client(workdir[0])
    pid = f.principal("cust-1")
    f.grant_consent(pid, "service")
    rid = f.submit_request(pid, requested_by="app")["request_id"]
    rows = c.get("/v1/erasure-requests", headers=_h("rev")).json()
    assert [r["request_id"] for r in rows] == [rid] and rows[0]["sign_off"] == "not_reviewable"
    f.process_jobs()
    rows = c.get("/v1/erasure-requests?sign_off=pending", headers=_h("dpo")).json()
    assert rows[0]["request_id"] == rid and rows[0]["status"].startswith("completed") and rows[0]["required"] >= 1
    assert c.get("/v1/erasure-requests?sign_off=approved", headers=_h("dpo")).json() == []
    assert c.get("/v1/erasure-requests", headers=_h("app")).status_code == 403
    assert "principal_id" not in rows[0]


def test_person_overview_for_the_dpo_only(workdir):
    c, f = _client(workdir[0])
    pid = f.principal("cust-1")
    f.grant_consent(pid, "service", actor="app")
    with f.context(pid, purpose="service"):
        p = f.protect("write to a@example.in")
        f.track_artifact("record", "notes", {"id": "n1"}, content=p.text, element_ids=p.element_ids)
    o = c.get("/v1/principals/cust-1/overview", headers=_h("dpo")).json()
    assert o["principal_id"] == pid and o["consents"][0]["purpose_id"] == "service"
    assert o["consent_history"]["verify"]["ok"] and o["lineage"][0]["store"] == "notes"
    assert "a@example.in" not in str(o)
    assert c.get("/v1/principals/cust-1/overview", headers=_h("rev")).status_code == 403
    assert c.get("/v1/principals/nobody/overview", headers=_h("dpo")).status_code == 404


@pytest.mark.parametrize("path", ["/v1/sla", "/v1/rights-requests", "/v1/breaches", "/v1/erasure-requests"])
def test_every_console_screen_needs_a_credential(workdir, path):
    c, _ = _client(workdir[0])
    assert c.get(path).status_code == 401
