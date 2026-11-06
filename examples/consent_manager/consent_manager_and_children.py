"""Offline: consent through a Consent Manager, a withdrawal that erases, and a child's consent by a verified parent.

    python examples/consent_manager/consent_manager_and_children.py

Simulates the Consent Manager's signed webhook (HMAC), so it needs no network or API key.
See docs/consent-managers.md and docs/children.md.
"""
from __future__ import annotations

import json
import os
import sqlite3
import sys
import tempfile
import time
from pathlib import Path

from dpdp_rights import DataRightsFramework
from dpdp_rights.consent.ledger import ChildProcessingRestricted, ConsentDenied, ParentalConsentRequired
from dpdp_rights.consent.managers import SCHEMA, sign_hmac
from dpdp_rights.core.config import FrameworkConfig

SECRET = "demo-only-secret"


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="dpdp-cm-"))
    os.environ["DEMO_CM_SECRET"] = SECRET
    db = sqlite3.connect(tmp / "app.db")
    db.execute("CREATE TABLE notes (id TEXT PRIMARY KEY, principal_id TEXT, body TEXT)")
    db.commit()
    dpdp = DataRightsFramework(FrameworkConfig.model_validate({
        "environment": "dev",
        "vault": {"local_master_key_path": str(tmp / "master.key")},
        "lineage": {"url": f"sqlite:///{tmp}/lineage.db"},
        "certificates": {"signer": "local", "local_key_path": str(tmp / "sign.key")},
        "purposes": [{"id": "learning", "description": "Run the learning app"},
                     {"id": "offers", "description": "Send offers"},
                     {"id": "personalised_ads", "child_restricted": True}],
        "connectors": [{"name": "notes", "type": "sql_table", "options": {
            "url": f"sqlite:///{tmp}/app.db", "table": "notes", "content_column": "body",
            "principal_column": "principal_id"}}],
        "consent_managers": [{"name": "demo_cm", "registration_ref": "DPB/CM/DEMO",
                              "verification": {"mode": "hmac", "secret_env": "DEMO_CM_SECRET"},
                              "purpose_map": {"OFFERS": "offers", "LEARN": "learning"},
                              "element_map": {"email": "EMAIL", "chat": "FREE_TEXT"}}],
        "children": {"enabled": True, "token_issuers": ["digilocker"]},
    }))
    cm = dpdp.consent_managers

    def webhook(etype, eid, ref, purposes, **extra):
        body = json.dumps({"schema": SCHEMA, "consent_manager": "demo_cm", "events": [{
            "event_id": eid, "type": etype, "occurred_at": "2026-11-18T10:00:00+05:30",
            "artefact": {"id": f"art-{ref}", "principal_ref": ref, "purposes": purposes,
                         "data_items": ["email", "chat"], "notice_version": "2026-11"}, **extra}]}).encode()
        ts = str(int(time.time()))
        return cm.receive("demo_cm", {"X-CM-Timestamp": ts, "X-CM-Signature": sign_hmac(SECRET, ts, body)},
                          body)["results"][0]

    # 1. An adult gives consent for offers through the Consent Manager.
    r = webhook("given", "e1", "CUST-1", ["OFFERS"])
    pid = r["principal_id"]
    dpdp.children.set_status(pid, "adult", basis="verified", set_by="kyc", verification_ref="kyc-1")
    with dpdp.context(pid, purpose="offers"):
        s = dpdp.protect("Send the festive offer to asha@example.in")
        db.execute("INSERT INTO notes VALUES ('n1', ?, ?)", (pid, s.text))
        db.commit()
        dpdp.track_artifact("record", "notes", {"id": "n1"}, content=s.text, element_ids=s.element_ids)
    print(f"1. consent via Consent Manager: {r['outcome']}; stored: {s.text}")
    assert webhook("given", "e1", "CUST-1", ["OFFERS"])["outcome"] == "duplicate"
    print("   redelivery: duplicate")

    # 2. They withdraw in the Consent Manager's app: erasure for that purpose is queued and run.
    r = webhook("withdrawn", "e2", "CUST-1", ["OFFERS"])
    done = dpdp.process_jobs()
    left = db.execute("SELECT count(*) FROM notes").fetchone()[0]
    print(f"2. withdrawal via Consent Manager: erasure {r['erasures'][0]['request_id']} "
          f"{'ok' if all(d['ok'] for d in done) else 'FAILED'}; rows left {left}")
    try:
        with dpdp.context(pid, purpose="offers"):
            dpdp.protect("another offer")
        return 1
    except ConsentDenied:
        print("   processing for offers is now refused")
    v = dpdp.consent_history.verify(pid)
    print(f"   consent history: {v['events']} signed events, chain ok={v['ok']}")

    # 3. A child: consent only from a parent verified through a DigiLocker token; no targeted ads at all.
    kid = dpdp.principal("STUDENT-7")
    dpdp.children.set_status(kid, "child", basis="declared", set_by="onboarding", verification_ref="onb-7")
    try:
        dpdp.grant_consent(kid, "learning")
        return 1
    except ParentalConsentRequired:
        print("3. child: consent without a verified parent is refused")
    g = dpdp.children.record_guardian(kid, dpdp.principal("PARENT-7"), method="virtual_token", issuer="digilocker",
                                      verification_ref="dl-txn-001", verified_by="kyc-service",
                                      relationship="father")
    dpdp.grant_consent(kid, "learning", guardian_id=g["guardian_id"], actor="parent-app")
    with dpdp.context(kid, purpose="learning"):
        dpdp.protect("Lesson 4 progress for the student")
    print(f"   consent from the verified parent ({g['method']}, {g['issuer']}) works")
    try:
        dpdp.grant_consent(kid, "personalised_ads", guardian_id=g["guardian_id"])
        return 1
    except ChildProcessingRestricted:
        print("   targeted ads are refused even with the parent's consent (s.9(3))")

    ok = left == 0 and v["ok"] and dpdp.consent_history.verify(kid)["ok"]
    print("OK" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
