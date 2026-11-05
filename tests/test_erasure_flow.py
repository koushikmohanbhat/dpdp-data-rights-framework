import json
import logging

import pytest

from dpdp_rights import EdgeType
from dpdp_rights.consent.ledger import ConsentDenied


def _record(dpdp, db, ext, text, purposes=("service",)):
    pid = dpdp.principal(ext)
    for p in purposes:
        dpdp.grant_consent(pid, p)
    with dpdp.context(pid, purpose="service"):
        safe = dpdp.protect(text)
        db.execute("INSERT INTO records VALUES (?,?,?)", (ext, pid, safe.text))
        db.commit()
        art = dpdp.track_artifact("record", "records", {"id": ext}, element_ids=safe.element_ids, content=safe.text)
    return pid, art, safe


def test_consent_is_purpose_specific(dpdp):
    pid = dpdp.principal("c")
    dpdp.grant_consent(pid, "service")
    with dpdp.context(pid, purpose="analytics"):
        with pytest.raises(ConsentDenied):
            dpdp.protect("email me at c@x.in")
    with dpdp.context(pid, purpose="kyc"):          # legitimate use: no consent needed
        assert "<EMAIL_" in dpdp.protect("c@x.in").text


def test_full_erasure_across_stores(dpdp, workdir):
    tmp, db = workdir
    p1, t1, s1 = _record(dpdp, db, "priya", "My name is Priya Sharma, mail priya@x.in, phone 9876543210")
    dpdp.register_identifier(p1, "EMAIL", "priya@x.in")
    p2, t2, _ = _record(dpdp, db, "rahul", "I am Rahul Verma. My wife's email is priya@x.in")
    p3, t3, _ = _record(dpdp, db, "anita", "I am Anita Rao. Health cover.")

    # eval row copied from Priya's record
    (tmp / "evals.jsonl").write_text(json.dumps({"id": "e1", "input": s1.text}) + "\n")
    with dpdp.context(p1, purpose="service"):
        dpdp.track_artifact("eval_row", "evals", {"id": "e1"}, parents=[t1.artifact_id], edge_type=EdgeType.COPY,
                           content=s1.text)
    # aggregate summary over three records (k=2 -> 2 others meets threshold -> retained, tokens redacted)
    db.execute("INSERT INTO summaries VALUES ('w', 'weekly: 3 records')")
    db.commit()
    dpdp.track_artifact("summary", "summaries", {"id": "w"}, parents=[t1.artifact_id, t2.artifact_id, t3.artifact_id],
                       edge_type=EdgeType.AGGREGATE, purpose="analytics")
    # tokenising log filter
    lg = logging.getLogger("t")
    h = logging.FileHandler(tmp / "app.log")
    h.addFilter(dpdp.logging_filter())
    lg.addHandler(h)
    lg.setLevel(logging.INFO)
    with dpdp.context(p1, purpose="service"):
        lg.info("callback 9876543210 for priya@x.in")
    h.close()
    assert "9876543210" not in (tmp / "app.log").read_text()

    plan = dpdp.erase(p1, dry_run=True)
    actions = {(p["store"], p["kind"]): p["action"] for p in plan["plan"]}
    assert plan["status"] == "planned"
    assert db.execute("SELECT count(*) FROM records").fetchone()[0] == 3   # dry run changed nothing

    res = dpdp.erase(p1)
    assert res["status"] == "completed", res
    assert db.execute("SELECT count(*) FROM records WHERE id='priya'").fetchone()[0] == 0
    rahul = db.execute("SELECT body FROM records WHERE id='rahul'").fetchone()[0]
    assert "[ERASED]" in rahul and "<EMAIL_" not in rahul           # third-party mention redacted, not deleted
    assert (tmp / "evals.jsonl").read_text().strip() == ""
    assert any(a == "retain_aggregate" for a in res["actions"])
    assert dpdp.store.get_certificate(res["request_id"])["sha256"] == res["certificate_sha256"]
    assert dpdp.vault.reveal(s1.text).count("[ERASED]") >= 3
    assert actions[("evals", "eval_row")] == "delete"


def test_purpose_scoped_withdrawal_keeps_other_data(dpdp, workdir):
    tmp, db = workdir
    pid, t1, safe = _record(dpdp, db, "c", "mail c@x.in", purposes=("service", "analytics"))
    db.execute("INSERT INTO summaries VALUES ('a1', ?)", (safe.text,))
    db.commit()
    with dpdp.context(pid, purpose="analytics"):
        dpdp.track_artifact("summary", "summaries", {"id": "a1"}, parents=[t1.artifact_id], content=safe.text)
    out = dpdp.withdraw_consent(pid, "analytics")
    assert out["withdrawn"] == 1
    assert db.execute("SELECT count(*) FROM records").fetchone()[0] == 1   # service data untouched
    assert dpdp.vault.has_key(pid)                                        # no full shred on purpose scope
    assert "<EMAIL_" not in db.execute("SELECT body FROM summaries WHERE id='a1'").fetchone()[0]


def test_legal_hold_and_model_retrain_are_exceptions(dpdp, workdir):
    tmp, db = workdir
    pid = dpdp.principal("k")
    with dpdp.context(pid, purpose="kyc"):
        safe = dpdp.protect("PAN ABCPR1234K")
        db.execute("INSERT INTO records VALUES ('k', ?, ?)", (pid, safe.text))
        db.commit()
        t = dpdp.track_artifact("record", "records", {"id": "k"}, content=safe.text, element_ids=safe.element_ids)
        dpdp.track_artifact("model", "models", {"name": "ft-1"}, parents=[t.artifact_id], edge_type=EdgeType.TRAIN,
                           purpose="service")
    res = dpdp.erase(pid)
    kinds = {e["action"] for e in res["exceptions"]}
    assert {"retain_legal_hold", "flag_retrain"} <= kinds
    assert db.execute("SELECT count(*) FROM records WHERE id='k'").fetchone()[0] == 1
    tok = safe.text.split()[-1]
    assert dpdp.vault.detokenize(tok, privileged=True) == "ABCPR1234K"   # sealed under legal-hold key


def test_unregistered_copy_found_by_discovery(dpdp, workdir):
    tmp, db = workdir
    pid, _, safe = _record(dpdp, db, "z", "mail z@x.in")
    tok = safe.text.split()[-1]
    db.execute("INSERT INTO summaries VALUES ('rogue', ?)", (f"note about {tok}",))
    db.commit()
    res = dpdp.erase(pid)
    assert db.execute("SELECT count(*) FROM summaries WHERE id='rogue'").fetchone()[0] in (0, 1)
    body = db.execute("SELECT body FROM summaries WHERE id='rogue'").fetchone()
    assert body is None or tok not in body[0]
    assert res["status"] == "completed"


def test_raw_pii_leak_fails_verification(dpdp, workdir):
    tmp, db = workdir
    pid, _, _ = _record(dpdp, db, "leaky", "phone 9876543210")
    (tmp / "app.log").write_text("legacy worker dialled 9876543210\n")
    res = dpdp.erase(pid)
    assert res["status"] == "completed_with_exceptions"
    assert any(not v["ok"] and v["store"] == "log" for v in res["verification"])


def test_statutory_escrow_recorded_and_purged(dpdp, workdir):
    from datetime import timedelta

    from dpdp_rights.core.models import utcnow

    tmp, db = workdir
    pid, _, safe = _record(dpdp, db, "esc", "mail esc@x.in")
    res = dpdp.erase(pid)
    esc = [e for e in res["exceptions"] if e["kind"] == "retention_escrow"]
    assert esc and "Rule 8(3)" in esc[0]["reason"]
    tok = safe.text.split()[-1]
    assert dpdp.vault.detokenize(tok) is None and dpdp.vault.detokenize(tok, privileged=True) == "esc@x.in"
    assert dpdp.orchestrator.purge_due_escrows() == []                       # window not over yet
    purged = dpdp.orchestrator.purge_due_escrows(now=utcnow() + timedelta(days=366))
    assert purged and dpdp.vault.detokenize(tok, privileged=True) is None
