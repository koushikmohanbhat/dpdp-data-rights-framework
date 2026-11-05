import json
import logging

import pytest

from dpdp_erasure import EdgeType
from dpdp_erasure.consent.ledger import ConsentDenied


def _ticket(kit, db, ext, text, purposes=("support",)):
    pid = kit.principal(ext)
    for p in purposes:
        kit.grant_consent(pid, p)
    with kit.context(pid, purpose="support"):
        safe = kit.protect(text)
        db.execute("INSERT INTO tickets VALUES (?,?,?)", (ext, pid, safe.text))
        db.commit()
        art = kit.track_artifact("record", "tickets", {"id": ext}, element_ids=safe.element_ids, content=safe.text)
    return pid, art, safe


def test_consent_is_purpose_specific(kit):
    pid = kit.principal("c")
    kit.grant_consent(pid, "support")
    with kit.context(pid, purpose="analytics"):
        with pytest.raises(ConsentDenied):
            kit.protect("email me at c@x.in")
    with kit.context(pid, purpose="kyc"):          # legitimate use: no consent needed
        assert "<EMAIL_" in kit.protect("c@x.in").text


def test_full_erasure_across_stores(kit, workdir):
    tmp, db = workdir
    p1, t1, s1 = _ticket(kit, db, "priya", "My name is Priya Sharma, mail priya@x.in, phone 9876543210")
    kit.register_identifier(p1, "EMAIL", "priya@x.in")
    p2, t2, _ = _ticket(kit, db, "rahul", "I am Rahul Verma. My wife's email is priya@x.in")
    p3, t3, _ = _ticket(kit, db, "anita", "I am Anita Rao. Late delivery.")

    # eval row copied from Priya's ticket
    (tmp / "evals.jsonl").write_text(json.dumps({"id": "e1", "input": s1.text}) + "\n")
    with kit.context(p1, purpose="support"):
        kit.track_artifact("eval_row", "evals", {"id": "e1"}, parents=[t1.artifact_id], edge_type=EdgeType.COPY,
                           content=s1.text)
    # aggregate summary over three tickets (k=2 -> 2 others meets threshold -> retained, tokens redacted)
    db.execute("INSERT INTO summaries VALUES ('w', 'weekly: 3 tickets')")
    db.commit()
    kit.track_artifact("summary", "summaries", {"id": "w"}, parents=[t1.artifact_id, t2.artifact_id, t3.artifact_id],
                       edge_type=EdgeType.AGGREGATE, purpose="analytics")
    # tokenising log filter
    lg = logging.getLogger("t")
    h = logging.FileHandler(tmp / "app.log")
    h.addFilter(kit.logging_filter())
    lg.addHandler(h)
    lg.setLevel(logging.INFO)
    with kit.context(p1, purpose="support"):
        lg.info("callback 9876543210 for priya@x.in")
    h.close()
    assert "9876543210" not in (tmp / "app.log").read_text()

    plan = kit.erase(p1, dry_run=True)
    actions = {(p["store"], p["kind"]): p["action"] for p in plan["plan"]}
    assert plan["status"] == "planned"
    assert db.execute("SELECT count(*) FROM tickets").fetchone()[0] == 3   # dry run changed nothing

    res = kit.erase(p1)
    assert res["status"] == "completed", res
    assert db.execute("SELECT count(*) FROM tickets WHERE id='priya'").fetchone()[0] == 0
    rahul = db.execute("SELECT body FROM tickets WHERE id='rahul'").fetchone()[0]
    assert "[ERASED]" in rahul and "<EMAIL_" not in rahul           # third-party mention redacted, not deleted
    assert (tmp / "evals.jsonl").read_text().strip() == ""
    assert any(a == "retain_aggregate" for a in res["actions"])
    assert kit.store.get_certificate(res["request_id"])["sha256"] == res["certificate_sha256"]
    assert kit.vault.reveal(s1.text).count("[ERASED]") >= 3
    assert actions[("evals", "eval_row")] == "delete"


def test_purpose_scoped_withdrawal_keeps_other_data(kit, workdir):
    tmp, db = workdir
    pid, t1, safe = _ticket(kit, db, "c", "mail c@x.in", purposes=("support", "analytics"))
    db.execute("INSERT INTO summaries VALUES ('a1', ?)", (safe.text,))
    db.commit()
    with kit.context(pid, purpose="analytics"):
        kit.track_artifact("summary", "summaries", {"id": "a1"}, parents=[t1.artifact_id], content=safe.text)
    out = kit.withdraw_consent(pid, "analytics")
    assert out["withdrawn"] == 1
    assert db.execute("SELECT count(*) FROM tickets").fetchone()[0] == 1   # support data untouched
    assert kit.vault.has_key(pid)                                        # no full shred on purpose scope
    assert "<EMAIL_" not in db.execute("SELECT body FROM summaries WHERE id='a1'").fetchone()[0]


def test_legal_hold_and_model_retrain_are_exceptions(kit, workdir):
    tmp, db = workdir
    pid = kit.principal("k")
    with kit.context(pid, purpose="kyc"):
        safe = kit.protect("PAN ABCPR1234K")
        db.execute("INSERT INTO tickets VALUES ('k', ?, ?)", (pid, safe.text))
        db.commit()
        t = kit.track_artifact("record", "tickets", {"id": "k"}, content=safe.text, element_ids=safe.element_ids)
        kit.track_artifact("model", "models", {"name": "ft-1"}, parents=[t.artifact_id], edge_type=EdgeType.TRAIN,
                           purpose="support")
    res = kit.erase(pid)
    kinds = {e["action"] for e in res["exceptions"]}
    assert {"retain_legal_hold", "flag_retrain"} <= kinds
    assert db.execute("SELECT count(*) FROM tickets WHERE id='k'").fetchone()[0] == 1
    tok = safe.text.split()[-1]
    assert kit.vault.detokenize(tok, privileged=True) == "ABCPR1234K"   # sealed under legal-hold key


def test_unregistered_copy_found_by_discovery(kit, workdir):
    tmp, db = workdir
    pid, _, safe = _ticket(kit, db, "z", "mail z@x.in")
    tok = safe.text.split()[-1]
    db.execute("INSERT INTO summaries VALUES ('rogue', ?)", (f"note about {tok}",))
    db.commit()
    res = kit.erase(pid)
    assert db.execute("SELECT count(*) FROM summaries WHERE id='rogue'").fetchone()[0] in (0, 1)
    body = db.execute("SELECT body FROM summaries WHERE id='rogue'").fetchone()
    assert body is None or tok not in body[0]
    assert res["status"] == "completed"


def test_raw_pii_leak_fails_verification(kit, workdir):
    tmp, db = workdir
    pid, _, _ = _ticket(kit, db, "leaky", "phone 9876543210")
    (tmp / "app.log").write_text("legacy worker dialled 9876543210\n")
    res = kit.erase(pid)
    assert res["status"] == "completed_with_exceptions"
    assert any(not v["ok"] and v["store"] == "log" for v in res["verification"])


def test_statutory_escrow_recorded_and_purged(kit, workdir):
    from datetime import timedelta

    from dpdp_erasure.core.models import utcnow

    tmp, db = workdir
    pid, _, safe = _ticket(kit, db, "esc", "mail esc@x.in")
    res = kit.erase(pid)
    esc = [e for e in res["exceptions"] if e["kind"] == "retention_escrow"]
    assert esc and "Rule 8(3)" in esc[0]["reason"]
    tok = safe.text.split()[-1]
    assert kit.vault.detokenize(tok) is None and kit.vault.detokenize(tok, privileged=True) == "esc@x.in"
    assert kit.orchestrator.purge_due_escrows() == []                       # window not over yet
    purged = kit.orchestrator.purge_due_escrows(now=utcnow() + timedelta(days=366))
    assert purged and kit.vault.detokenize(tok, privileged=True) is None
