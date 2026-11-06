"""Consent Managers (Act s.6(7)-(9), Rules r.4) and the signed consent history (s.6(10)): docs/consent-managers.md."""
import base64
import hashlib
import hmac
import json
import threading
import time
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from test_rights import _cfg

from dpdp_rights import DataRightsFramework
from dpdp_rights.api.app import create_app
from dpdp_rights.consent.ledger import ConsentDenied
from dpdp_rights.consent.managers import SCHEMA, CmEventError, SignatureError, sign_hmac
from dpdp_rights.core.models import utcnow
from dpdp_rights.security.auth import hash_api_key
from dpdp_rights.security.guardrails import production_issues

SECRET = "cm-test-secret"


def _cm(**kw):
    base = {"name": "sahmati", "registration_ref": "DPB-CM-0001",
            "verification": {"mode": "hmac", "secret_env": "CM_SECRET"},
            "purpose_map": {"MKTG": "marketing", "SVC": "service"},
            "element_map": {"email": "EMAIL", "mobile": "PHONE_IN", "chat": "FREE_TEXT"}}
    base.update(kw)
    return base


@pytest.fixture
def cmf(workdir, monkeypatch):
    monkeypatch.setenv("CM_SECRET", SECRET)
    tmp, _ = workdir
    return DataRightsFramework(_cfg(tmp, consent_managers=[_cm()]))


def _event(etype, eid, artefact="art-1", ref="cust-1", purposes=("MKTG",), items=("email", "chat"), **kw):
    art = {"id": artefact, "principal_ref": ref, "purposes": list(purposes), "data_items": list(items),
           "notice_version": "2026-11"}
    art.update(kw.pop("art", {}))
    return {"event_id": eid, "type": etype, "occurred_at": "2026-11-18T10:00:00+05:30", "artefact": art, **kw}


def _body(*events, cm="sahmati"):
    return json.dumps({"schema": SCHEMA, "consent_manager": cm, "events": list(events)}).encode()


def _signed(body, secret=SECRET, ts=None):
    ts = str(int(ts if ts is not None else time.time()))
    return {"X-CM-Timestamp": ts, "X-CM-Signature": sign_hmac(secret, ts, body)}


def _send(f, *events, **kw):
    body = _body(*events)
    return f.consent_managers.receive("sahmati", _signed(body, **kw), body)["results"]


def _pid(f, ext="cust-1"):
    return f.vault.resolve_principal(ext, create=False)


# ---- given / denied ---------------------------------------------------------------------------------------
def test_a_consent_given_through_the_consent_manager_is_recorded_and_lets_processing_run(cmf):
    r = _send(cmf, _event("given", "ev-1"))
    assert r[0]["outcome"] == "applied" and r[0]["purposes"] == ["marketing"]
    pid = _pid(cmf)
    rows = cmf.store.consents_for(pid)
    assert [(c["purpose_id"], c["element_type"], c["consent_manager_ref"]) for c in rows] == \
        [("marketing", "EMAIL", "sahmati:art-1"), ("marketing", "FREE_TEXT", "sahmati:art-1")]
    with cmf.context(pid, purpose="marketing"):
        cmf.protect("write to a1@example.in")
    ev = cmf.consent_history.events(pid)
    assert [e["kind"] for e in ev] == ["given"]
    assert ev[0]["source"] == "consent_manager:sahmati" and ev[0]["body"]["cm_event_id"] == "ev-1"
    assert ev[0]["body"]["registration_ref"] == "DPB-CM-0001" and ev[0]["signed"]
    assert cmf.store.get_artefact("sahmati:art-1")["status"] == "active"


def test_a_denial_is_recorded_without_granting_anything(cmf):
    assert _send(cmf, _event("given", "ev-0", artefact="a0", purposes=["SVC"]))[0]["outcome"] == "applied"
    assert _send(cmf, _event("denied", "ev-1", purposes=["MKTG"]))[0]["outcome"] == "recorded"
    pid = _pid(cmf)
    assert not cmf.ledger.has_effective(pid, "marketing")
    assert [e["kind"] for e in cmf.consent_history.events(pid)] == ["given", "denied"]


@pytest.mark.parametrize("event,reason", [
    (_event("given", "x1", purposes=["UNKNOWN"]), "purposes not mapped"),
    (_event("given", "x2", items=["aadhaar"]), "data items not mapped"),
    (_event("given", "x3", art={"valid_until": "2020-01-01T00:00:00+00:00"}), "already expired"),
])
def test_events_that_cannot_be_applied_are_refused_and_recorded(cmf, event, reason):
    r = _send(cmf, event)[0]
    assert r["outcome"] == "refused" and reason in r["reason"]
    pid = _pid(cmf)
    assert cmf.store.consents_for(pid) == []
    assert cmf.consent_history.events(pid)[-1]["kind"] == "consent_manager_event_refused"


def test_a_withdrawal_for_someone_unknown_is_refused_and_creates_no_one(cmf):
    r = _send(cmf, _event("withdrawn", "w-1", ref="nobody"))[0]
    assert r == {"event_id": "w-1", "type": "withdrawn", "outcome": "refused", "reason": "unknown principal reference"}
    assert _pid(cmf, "nobody") is None


# ---- withdrawal and expiry ----------------------------------------------------------------------------------
def test_withdrawal_through_the_consent_manager_queues_a_purpose_scoped_erasure(cmf):
    _send(cmf, _event("given", "g-1"))
    pid = _pid(cmf)
    r = _send(cmf, _event("withdrawn", "w-1"))[0]
    assert r["outcome"] == "applied" and r["withdrawn"] == 2 and r["still_held"] == []
    req = cmf.store.get_request(r["erasures"][0]["request_id"])
    assert req["scope"] == "purpose:marketing" and req["verified_by"] == "consent_manager:sahmati"
    assert req["verification_ref"] == "w-1" and req["requested_by"] == "consent_manager:sahmati"
    with cmf.context(pid, purpose="marketing"), pytest.raises(ConsentDenied):
        cmf.protect("write to a1@example.in")
    done = cmf.process_jobs()
    assert done and all(d["ok"] for d in done)
    kinds = [e["kind"] for e in cmf.consent_history.events(pid)]
    assert kinds == ["given", "withdrawn"]      # the worker found nothing more to withdraw and reported nothing back
    assert cmf.store.get_artefact("sahmati:art-1")["status"] == "withdrawn"


def test_withdrawing_one_artefact_keeps_consent_given_another_way(cmf):
    _send(cmf, _event("given", "g-1"))
    pid = _pid(cmf)
    cmf.grant_consent(pid, "marketing", actor="app")            # also given directly
    r = _send(cmf, _event("withdrawn", "w-1"))[0]
    assert r["still_held"] == ["marketing"] and r["erasures"] == []
    assert cmf.ledger.has_effective(pid, "marketing")


def test_a_withdrawal_can_be_turned_into_consent_only_with_erase_on_withdrawal_off(workdir, monkeypatch):
    monkeypatch.setenv("CM_SECRET", SECRET)
    tmp, _ = workdir
    f = DataRightsFramework(_cfg(tmp, consent_managers=[_cm(erase_on_withdrawal=False)]))
    _send(f, _event("given", "g-1"))
    assert _send(f, _event("withdrawn", "w-1"))[0]["erasures"] == []


def test_an_artefact_past_its_validity_stops_counting_and_expire_due_erases(cmf):
    soon = (utcnow() + timedelta(seconds=2)).isoformat()
    _send(cmf, _event("given", "g-1", art={"valid_until": soon}))
    pid = _pid(cmf)
    assert cmf.ledger.has_effective(pid, "marketing")
    art = cmf.store.get_artefact("sahmati:art-1")
    cmf.store.put_artefact({**art, "valid_until": utcnow() - timedelta(seconds=1)})
    assert not cmf.ledger.has_effective(pid, "marketing")       # no event needed for processing to stop
    out = cmf.consent_managers.expire_due()
    assert len(out) == 1 and out[0]["erasures"][0]["purpose"] == "marketing"
    assert cmf.store.get_artefact("sahmati:art-1")["status"] == "expired"
    assert cmf.consent_managers.expire_due() == []
    assert cmf.consent_history.events(pid)[-1]["kind"] == "expired"


def test_an_expiry_event_is_treated_like_a_withdrawal(cmf):
    _send(cmf, _event("given", "g-1"))
    r = _send(cmf, _event("expired", "e-1"))[0]
    assert r["outcome"] == "applied" and r["erasures"] and cmf.store.get_artefact("sahmati:art-1")["status"] == "expired"
    assert _send(cmf, _event("given", "g-2"))[0]["outcome"] == "refused"   # an ended artefact is not revived


# ---- exactly once ---------------------------------------------------------------------------------------------
def test_redelivered_events_are_applied_once(cmf):
    _send(cmf, _event("given", "g-1"))
    assert _send(cmf, _event("given", "g-1"))[0]["outcome"] == "duplicate"
    assert len(cmf.store.consents_for(_pid(cmf))) == 2      # EMAIL and FREE_TEXT, once each


def test_concurrent_deliveries_of_one_event_apply_it_once(cmf):
    _send(cmf, _event("given", "seed", artefact="a0"))       # principal exists first
    outcomes, errors = [], []

    def go():
        try:
            outcomes.append(_send(cmf, _event("given", "same", artefact="a1"))[0]["outcome"])
        except Exception as e:  # noqa: BLE001
            errors.append(e)
    ts = [threading.Thread(target=go) for _ in range(6)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert not errors and outcomes.count("applied") == 1
    assert set(outcomes) <= {"applied", "duplicate", "in_progress"}
    assert sum(1 for c in cmf.store.consents_for(_pid(cmf)) if c["consent_manager_ref"] == "sahmati:a1") == 2


def test_a_failed_application_releases_the_claim_so_a_redelivery_can_apply_it(cmf, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("database went away")
    with monkeypatch.context() as m:
        m.setattr(cmf.ledger, "grant", boom)
        with pytest.raises(RuntimeError):
            _send(cmf, _event("given", "g-1"))
    assert _send(cmf, _event("given", "g-1"))[0]["outcome"] == "applied"


# ---- authenticity ----------------------------------------------------------------------------------------------
@pytest.mark.parametrize("mutate,msg", [
    (lambda h, b: ({"X-CM-Timestamp": h["X-CM-Timestamp"]}, b), "missing"),
    (lambda h, b: (h, b + b" "), "does not match"),
    (lambda h, b: (_signed(b, secret="wrong"), b), "does not match"),
    (lambda h, b: (_signed(b, ts=time.time() - 3600), b), "replay window"),
    (lambda h, b: (_signed(b, ts=time.time() + 3600), b), "replay window"),
    (lambda h, b: ({"X-CM-Timestamp": "soon", "X-CM-Signature": "x"}, b), "Unix seconds"),
])
def test_unsigned_altered_or_replayed_events_are_refused(cmf, mutate, msg):
    body = _body(_event("given", "g-1"))
    h, b = mutate(_signed(body), body)
    with pytest.raises(SignatureError, match=msg):
        cmf.consent_managers.receive("sahmati", h, b)
    assert _pid(cmf) is None


def test_ed25519_signed_events_verify_against_the_published_key(workdir):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    tmp, _ = workdir
    key, other = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    pem = key.public_key().public_bytes(serialization.Encoding.PEM,
                                        serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    f = DataRightsFramework(_cfg(tmp, consent_managers=[_cm(verification={"mode": "ed25519", "public_key_pem": pem})]))
    body, ts = _body(_event("given", "g-1")), str(int(time.time()))

    def sig(k):
        return {"X-CM-Timestamp": ts, "X-CM-Signature": "ed25519=" + base64.b64encode(k.sign(ts.encode() + b"." + body)).decode()}
    with pytest.raises(SignatureError):
        f.consent_managers.receive("sahmati", sig(other), body)
    assert f.consent_managers.receive("sahmati", sig(key), body)["results"][0]["outcome"] == "applied"


@pytest.mark.parametrize("doc,msg", [
    ({"schema": "other/1", "consent_manager": "sahmati", "events": [_event("given", "a")]}, "schema"),
    ({"schema": SCHEMA, "consent_manager": "someone-else", "events": [_event("given", "a")]}, "consent_manager"),
    ({"schema": SCHEMA, "consent_manager": "sahmati", "events": []}, "non-empty"),
    ({"schema": SCHEMA, "consent_manager": "sahmati", "events": [_event("revived", "a")]}, "type must be"),
    ({"schema": SCHEMA, "consent_manager": "sahmati", "events": [_event("given", "")]}, "event_id is required"),
    ({"schema": SCHEMA, "consent_manager": "sahmati", "events": [_event("given", "a", purposes=[])]}, "purposes"),
    ({"schema": SCHEMA, "consent_manager": "sahmati",
      "events": [_event("given", "a", art={"valid_until": "2027-01-01T00:00:00"})]}, "time zone"),
])
def test_bodies_that_do_not_match_the_schema_are_refused(cmf, doc, msg):
    body = json.dumps(doc).encode()
    with pytest.raises(CmEventError, match=msg):
        cmf.consent_managers.receive("sahmati", _signed(body), body)


# ---- withdrawals made directly are reported back ---------------------------------------------------------------
class _Resp:
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_a_withdrawal_made_directly_is_reported_to_the_consent_manager_signed(workdir, monkeypatch):
    monkeypatch.setenv("CM_SECRET", SECRET)
    tmp, _ = workdir
    sent = []

    def opener(req, timeout):
        sent.append(req)
        return _Resp()
    f = DataRightsFramework(_cfg(tmp, consent_managers=[_cm(report_url="https://cm.example/v1/withdrawals")]))
    f.consent_managers._opener = opener
    _send(f, _event("given", "g-1"))
    pid = _pid(f)
    f.withdraw_consent(pid, "marketing", actor="app")
    assert len(sent) == 1
    req = sent[0]
    body = req.data
    assert hmac.compare_digest(req.get_header("X-cm-signature"), sign_hmac(SECRET, req.get_header("X-cm-timestamp"), body))
    ev = json.loads(body)["events"][0]
    assert ev["artefact_id"] == "art-1" and ev["purposes"] == ["marketing"] and ev["withdrawn_via"] == "data_fiduciary"
    last = f.consent_history.events(pid)[-1]
    assert last["kind"] == "reported_to_consent_manager" and last["body"]["ok"] is True


def test_a_failed_report_never_stops_the_withdrawal_and_is_recorded(workdir, monkeypatch):
    monkeypatch.setenv("CM_SECRET", SECRET)
    tmp, _ = workdir

    def opener(req, timeout):
        raise OSError("connection refused")
    f = DataRightsFramework(_cfg(tmp, consent_managers=[_cm(report_url="https://cm.example/v1/withdrawals")]))
    f.consent_managers._opener = opener
    _send(f, _event("given", "g-1"))
    pid = _pid(f)
    out = f.withdraw_consent(pid, "marketing", actor="app", erase=False)
    assert out["withdrawn"] == 2 and not f.ledger.has_effective(pid, "marketing")
    last = f.consent_history.events(pid)[-1]
    assert last["body"]["ok"] is False and "connection refused" in last["body"]["error"]


# ---- the consent history -----------------------------------------------------------------------------------------
def test_the_history_is_hash_chained_signed_and_tamper_evident(cmf):
    from sqlalchemy import update

    from dpdp_rights.lineage.store import consent_event

    pid = cmf.principal("direct-1")
    cmf.grant_consent(pid, "service", actor="app", verification_ref="sess-77")
    cmf.deny_consent(pid, "marketing", actor="app")
    cmf.withdraw_consent(pid, "service", erase=False, actor="app")
    v = cmf.consent_history.verify(pid)
    assert v == {"principal_id": pid, "ok": True, "events": 3, "broken_at": None, "signatures_ok": True}
    assert [e["kind"] for e in cmf.consent_history.events(pid)] == ["given", "denied", "withdrawn"]
    pem = cmf.orchestrator.signer.public_key_pem()
    assert cmf.consent_history.verify(pid, public_key_pem=pem)["ok"]
    with cmf.store.engine.begin() as c:
        c.execute(update(consent_event).where(consent_event.c.principal_id == pid, consent_event.c.kind == "denied")
                  .values(body=json.dumps({"purpose_id": "service"})))
    bad = cmf.consent_history.verify(pid)
    assert not bad["ok"] and bad["broken_at"]


def test_concurrent_consent_changes_keep_one_unbroken_chain(cmf):
    pid = cmf.principal("busy")
    errors = []

    def go(i):
        try:
            cmf.grant_consent(pid, "service" if i % 2 else "marketing", actor=f"t{i}")
        except Exception as e:  # noqa: BLE001
            errors.append(e)
    ts = [threading.Thread(target=go, args=(i,)) for i in range(8)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert not errors
    v = cmf.consent_history.verify(pid)
    assert v["ok"] and v["events"] == 8


def test_history_bodies_hold_references_not_values(cmf):
    _send(cmf, _event("given", "g-1", ref="cust-9"))
    text = json.dumps(cmf.consent_history.events(_pid(cmf, "cust-9")))
    assert "cust-9" not in text and "@" not in text


# ---- configuration -------------------------------------------------------------------------------------------------
def test_mappings_must_point_at_configured_purposes(workdir):
    tmp, _ = workdir
    with pytest.raises(ValueError, match="unknown purposes"):
        DataRightsFramework(_cfg(tmp, consent_managers=[_cm(purpose_map={"X": "nope"})]))


def test_production_check_requires_verifiable_consent_managers(workdir):
    tmp, _ = workdir
    issues = dict((m, lvl) for lvl, m in production_issues(_cfg(tmp, consent_managers=[
        _cm(name="a", verification={"mode": "hmac"}), _cm(name="b", verification={"mode": "hmac", "secret": "x"}),
        _cm(name="c", verification={"mode": "ed25519"}), _cm(name="d", registration_ref=None,
                                                             verification={"secret_env": "S", "replay_window_seconds": 3600})])))
    assert issues["consent manager 'a': no shared secret, so its events cannot be verified"] == "error"
    assert issues["consent manager 'b': secret is inline in the config; use secret_env"] == "error"
    assert issues["consent manager 'c': no public key, so its events cannot be verified"] == "error"
    assert any("replay window" in m for m in issues) and any("registration_ref" in m for m in issues)


def test_a_consent_manager_plug_in_is_used_by_type(workdir, monkeypatch):
    from dpdp_rights import plugins
    from dpdp_rights.consent.managers import CmEvent

    class Fake:
        def __init__(self, cfg, opener=None):
            pass

        def verify(self, headers, body):
            if headers.get("authorization") != "Bearer ok":
                raise SignatureError("no")

        def parse(self, body):
            return [CmEvent("p-1", "given", "x", "cust-1", ["SVC"])]
    monkeypatch.setitem(plugins._builtins["consent_managers"], "fake_cm", Fake)
    tmp, _ = workdir
    f = DataRightsFramework(_cfg(tmp, consent_managers=[_cm(type="fake_cm")]))
    assert f.consent_managers.receive("sahmati", {"authorization": "Bearer ok"}, b"{}")["results"][0]["outcome"] == "applied"


# ---- API and CLI ----------------------------------------------------------------------------------------------------
def test_api_webhook_and_consent_history(workdir, monkeypatch):
    monkeypatch.setenv("CM_SECRET", SECRET)
    tmp, _ = workdir
    keys = {"dpo": ["dpo"], "app": ["service"]}
    cfg = _cfg(tmp, consent_managers=[_cm()], api={"auth": {"mode": "api_key", "api_keys": [
        {"name": n, "sha256": hash_api_key(f"k-{n}"), "roles": r} for n, r in keys.items()]}})
    client = TestClient(create_app(config=cfg))
    body = _body(_event("given", "g-1"))
    r = client.post("/v1/consent-managers/sahmati/events", content=body, headers=_signed(body))
    assert r.status_code == 200 and r.json()["results"][0]["outcome"] == "applied"
    assert client.post("/v1/consent-managers/sahmati/events", content=body,
                       headers=_signed(body, secret="x")).status_code == 401
    assert client.post("/v1/consent-managers/other/events", content=body, headers=_signed(body)).status_code == 404
    bad = b'{"schema": "x"}'
    assert client.post("/v1/consent-managers/sahmati/events", content=bad, headers=_signed(bad)).status_code == 422
    h = client.get("/v1/principals/cust-1/consent-history", headers={"X-API-Key": "k-dpo"}).json()
    assert h["verify"]["ok"] and h["events"][0]["source"] == "consent_manager:sahmati"
    assert client.get("/v1/principals/cust-1/consent-history", headers={"X-API-Key": "k-app"}).status_code == 403
    assert client.get("/v1/consent-managers", headers={"X-API-Key": "k-dpo"}).json()[0]["registration_ref"] == "DPB-CM-0001"
    r = client.post("/v1/consent-denials", json={"external_id": "cust-1", "purpose_id": "service"},
                    headers={"X-API-Key": "k-app"})
    assert r.status_code == 201


def test_cli_receive_and_history(workdir, monkeypatch, capsys):
    import yaml

    from dpdp_rights.cli import main

    monkeypatch.setenv("CM_SECRET", SECRET)
    tmp, _ = workdir
    cfg = _cfg(tmp, consent_managers=[_cm()]).model_dump()
    (tmp / "c.yaml").write_text(yaml.safe_dump(cfg))
    body = _body(_event("given", "g-1"))
    (tmp / "ev.json").write_bytes(body)
    h = _signed(body)
    main(["-c", str(tmp / "c.yaml"), "consent-managers", "receive", "sahmati", "--body", str(tmp / "ev.json"),
          "--timestamp", h["X-CM-Timestamp"], "--signature", h["X-CM-Signature"]])
    assert json.loads(capsys.readouterr().out)["results"][0]["outcome"] == "applied"
    with pytest.raises(SystemExit) as ex:
        main(["-c", str(tmp / "c.yaml"), "consent", "verify", "--external-id", "cust-1"])
    assert ex.value.code == 0 and json.loads(capsys.readouterr().out)["ok"]
    main(["-c", str(tmp / "c.yaml"), "consent", "history", "--external-id", "cust-1"])
    assert json.loads(capsys.readouterr().out)[0]["kind"] == "given"


def test_receipt_keys_do_not_reveal_event_ids(cmf):
    from sqlalchemy import select

    from dpdp_rights.lineage.store import cm_event_receipt

    _send(cmf, _event("given", "g-1"))
    with cmf.store.engine.connect() as c:
        row = c.execute(select(cm_event_receipt)).first()
    assert row.receipt_key == hashlib.sha256(b"sahmati\x00g-1").hexdigest() and row.outcome == "applied"
