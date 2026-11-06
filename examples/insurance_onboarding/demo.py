"""End-to-end demo: an insurance onboarding agent.

Applicants talk to an AI agent to buy term-life, motor, health and travel cover.
Their data spreads into application records, KYC records, document embeddings,
an agent response cache, underwriting summaries, a marketing audience, an eval
set, logs and a weekly portfolio report. Later:

  * Anita withdraws consent for marketing only  -> purpose-scoped erasure
  * Priya withdraws all consent and asks to be erased -> full erasure, with the KYC
    record kept under a legal hold and a sealed statutory-retention escrow

The same flow applies to any agent (lending, healthcare, telecom, retail, HR...):
only the purposes and stores change, in config/dpdp.local.yaml.

Runs fully offline (echo model, local vault, SQLite):

    python examples/insurance_onboarding/demo.py            # clean run
    python examples/insurance_onboarding/demo.py --leak     # a legacy job logs a raw phone number
    python examples/insurance_onboarding/demo.py --html     # also write .dpdp/report.html (open in a browser)
    DPDP_PROVIDER=openai DPDP_MODEL=gpt-5-mini python examples/insurance_onboarding/demo.py
    DPDP_PROVIDER=anthropic DPDP_MODEL=claude-sonnet-5-5 python examples/insurance_onboarding/demo.py
"""
from __future__ import annotations

import argparse
import json
import logging
import re
import shutil
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from dpdp_rights import DataRightsFramework, EdgeType  # noqa: E402
from dpdp_rights.consent.ledger import ConsentDenied  # noqa: E402
from dpdp_rights.pii.detectors import verhoeff_check_digit  # noqa: E402

STATE = Path(".dpdp")
CFG = ROOT / "config" / "dpdp.local.yaml"
AGENT_SYSTEM = "You are an insurance onboarding agent. Collect details, explain cover and next steps."


def fake_aadhaar(prefix: str) -> str:
    n = prefix + verhoeff_check_digit(prefix)
    return f"{n[:4]} {n[4:8]} {n[8:]}"


def setup_app_db() -> sqlite3.Connection:
    db = sqlite3.connect(STATE / "app.db")
    db.executescript("""
        CREATE TABLE applications (id TEXT PRIMARY KEY, principal_id TEXT, body TEXT);
        CREATE TABLE kyc_records  (id TEXT PRIMARY KEY, principal_id TEXT, body TEXT);
        CREATE TABLE summaries    (id TEXT PRIMARY KEY, body TEXT);
        CREATE TABLE chunks       (id TEXT PRIMARY KEY, chunk TEXT, embedding TEXT);
        CREATE TABLE cache        (id TEXT PRIMARY KEY, question TEXT, answer TEXT);
        CREATE TABLE audiences    (id TEXT PRIMARY KEY, principal_id TEXT, body TEXT);
    """)
    return db


def hr(title: str) -> None:
    print(f"\n{'=' * 78}\n{title}\n{'=' * 78}")


def one(db, sql, *args):
    r = db.execute(sql, args).fetchone()
    return r[0] if r else None


APPLICANTS = {
    "app-1001": dict(
        name="Priya Sharma", product="term life", email="priya.sharma@example.in", phone="+91 98765 43210",
        consents=["policy_issuance", "analytics", "marketing", "model_improvement"],
        text=(f"My name is Priya Sharma. I want a 1 crore term plan. Aadhaar {fake_aadhaar('23456789012')}, "
              "PAN ABCPS1234K. Reach me on +91 98765 43210 or priya.sharma@example.in. Non-smoker, age 34.")),
    "app-1002": dict(
        name="Rahul Verma", product="motor", email="rahul.v@example.in", phone="+91 91234 56789",
        consents=["policy_issuance", "analytics", "marketing"],
        text=("My name is Rahul Verma. Comprehensive cover for KA-01-AB-1234. Nominee is my wife, "
              "email priya.sharma@example.in. Premium via UPI rahulv@okhdfc.")),
    "app-1003": dict(
        name="Anita Rao", product="health", email="anita.rao@example.in", phone="+91 99887 76655",
        consents=["policy_issuance", "analytics", "marketing"],
        text="Mera naam Anita Rao hai, PAN ABCPR1234K. Family floater chahiye, 2 adults aur 1 child."),   # Hinglish
    "app-1004": dict(
        name="Vikram Iyer", product="travel", email="vikram@example.in", phone="+91 90000 11111",
        consents=["policy_issuance", "analytics"],
        text="मेरा नाम विक्रम अय्यर है। Schengen travel cover, 12 days in December. Pay by card 4111 1111 1111 1111."),
}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--leak", action="store_true", help="a legacy job writes a raw phone number to the log")
    ap.add_argument("--html", nargs="?", const=str(STATE / "report.html"), metavar="PATH",
                    help="also write a self-contained HTML report (default .dpdp/report.html)")
    args = ap.parse_args()

    shutil.rmtree(STATE, ignore_errors=True)
    (STATE / "evals").mkdir(parents=True)
    db = setup_app_db()
    dpdp = DataRightsFramework.from_yaml(str(CFG))

    log = logging.getLogger("onboarding-agent")
    log.setLevel(logging.INFO)
    fh = logging.FileHandler(STATE / "app.log")
    fh.setFormatter(logging.Formatter("%(asctime)s principal=%(dpdp_principal)s purpose=%(dpdp_purpose)s %(message)s"))
    fh.addFilter(dpdp.logging_filter())
    log.addHandler(fh)

    R: dict = {"applicants": [], "person": "Priya", "leak": args.leak,
               "purposes": ["policy_issuance", "analytics", "marketing", "model_improvement"]}

    hr("1. Applicants talk to the onboarding agent (purpose-specific consent captured per applicant)")
    apps: dict[str, str] = {}
    pids: dict[str, str] = {}
    for ext, a in APPLICANTS.items():
        pid = dpdp.principal(ext)
        pids[ext] = pid
        dpdp.register_identifier(pid, "EMAIL", a["email"])
        dpdp.register_identifier(pid, "PHONE_IN", a["phone"])
        for purpose in a["consents"]:
            dpdp.grant_consent(pid, purpose, notice_version="2026-11")

        with dpdp.context(pid, purpose="policy_issuance", session_id=f"s-{ext}"):
            safe = dpdp.protect(a["text"])
            db.execute("INSERT INTO applications VALUES (?,?,?)", (ext, pid, safe.text))
            app_art = dpdp.track_artifact("record", "applications", {"id": ext}, element_ids=safe.element_ids,
                                          content=safe.text)
            apps[ext] = app_art.artifact_id
            log.info("application %s received for %s cover: %s", ext, a["product"], a["text"])  # filter tokenises

            vec = dpdp.embed([safe.text])[0]
            db.execute("INSERT INTO chunks VALUES (?,?,?)", (f"C-{ext}", safe.text, json.dumps(vec)))
            dpdp.track_artifact("embedding", "vectors", {"id": f"C-{ext}"}, parents=[app_art.artifact_id],
                                edge_type=EdgeType.EMBED, content=safe.text)

            ans = dpdp.generate(safe.text, system=AGENT_SYSTEM, already_protected=True)
            db.execute("INSERT INTO cache VALUES (?,?,?)", (f"K-{ext}", safe.text[:60], ans.text))
            dpdp.track_artifact("cache_entry", "agent_cache", {"id": f"K-{ext}"}, parents=[app_art.artifact_id],
                                content=ans.text)

            uw = f"Underwriting note ({a['product']}): risk standard, proceed to issue. Ref {safe.text[-48:]}"
            db.execute("INSERT INTO summaries VALUES (?,?)", (f"UW-{ext}", uw))
            dpdp.track_artifact("summary", "summaries", {"id": f"UW-{ext}"}, parents=[app_art.artifact_id],
                                edge_type=EdgeType.TRANSFORM, content=uw)

        if "marketing" in a["consents"]:
            with dpdp.context(pid, purpose="marketing"):
                row = f"Cross-sell audience: {a['product']} holder, contact {dpdp.vault.tokenize(pid, 'EMAIL', a['email'])}"
                db.execute("INSERT INTO audiences VALUES (?,?,?)", (f"M-{ext}", pid, row))
                dpdp.track_artifact("record", "audiences", {"id": f"M-{ext}"}, parents=[app_art.artifact_id],
                                    edge_type=EdgeType.COPY, content=row)
        db.commit()
        print(f"  {ext} ({a['product']:<9}) -> {pid}  stored as: {safe.text[:70]}...")
        R["applicants"].append({
            "ext": ext, "name": a["name"], "product": a["product"], "pid": pid, "consents": a["consents"],
            "raw": a["text"], "stored": safe.text,
            "spans": [(e.start, e.end, e.type) for e in dpdp.tokenizer.detector.detect(a["text"])]})

    p1 = pids["app-1001"]
    with dpdp.context(p1, purpose="kyc_regulatory"):       # legitimate use; retention required by law
        kyc = dpdp.protect(f"KYC verified. Aadhaar {fake_aadhaar('23456789012')}, PAN ABCPS1234K")
        db.execute("INSERT INTO kyc_records VALUES ('KYC-1001', ?, ?)", (p1, kyc.text))
        dpdp.track_artifact("record", "kyc_records", {"id": "KYC-1001"}, element_ids=kyc.element_ids, content=kyc.text)

    with dpdp.context(p1, purpose="model_improvement"):
        row = {"id": "eval-001", "input": one(db, "SELECT body FROM applications WHERE id='app-1001'"),
               "ideal": "Confirm sum assured, explain medical tests, list documents needed."}
        (STATE / "evals" / "agent_golden.jsonl").write_text(json.dumps(row) + "\n")
        dpdp.track_artifact("eval_row", "eval_set", {"id": "eval-001"}, parents=[apps["app-1001"]],
                            edge_type=EdgeType.COPY, content=row["input"])

    weekly = ("Weekly portfolio: 4 applications (term life, motor, health, travel); 3 opted into cross-sell; "
              "one high sum-assured term case pending medicals.")
    db.execute("INSERT INTO summaries VALUES ('PORTFOLIO-W45', ?)", (weekly,))
    dpdp.track_artifact("summary", "summaries",
                        {"id": "PORTFOLIO-W45",
                         "regen_instruction": "Write a weekly portfolio summary from these applications. No names."},
                        parents=list(apps.values()), edge_type=EdgeType.AGGREGATE, purpose="analytics")

    # A cache row written by a code path that bypassed the framework (never registered in lineage)
    tok_email = dpdp.vault.tokenize(p1, "EMAIL", "priya.sharma@example.in")
    db.execute("INSERT INTO cache VALUES ('K-rogue', 'policy status?', ?)", (f"Sent policy PDF to {tok_email}",))
    db.commit()
    if args.leak:
        with open(STATE / "app.log", "a") as f:
            f.write("2026-11-05 legacy-dialer DEBUG outbound call to +91 98765 43210 failed\n")

    counts_before = table_counts(db, p1)
    R["weekly_before"] = weekly

    hr("2. Anita withdraws consent for marketing only")
    p3 = pids["app-1003"]
    out = dpdp.withdraw_consent(p3, "marketing")
    print(f"  consents withdrawn: {out['withdrawn']}; actions: {out['erasure']['actions']}")
    print("  Anita's audience row left:", one(db, "SELECT count(*) FROM audiences WHERE id='M-app-1003'"))
    print("  Anita's application left: ", one(db, "SELECT count(*) FROM applications WHERE id='app-1003'"),
          "(policy issuance consent still active)")
    R["anita"] = {"name": "Anita",
                  "audience_after": one(db, "SELECT count(*) FROM audiences WHERE id='M-app-1003'"),
                  "application_after": one(db, "SELECT count(*) FROM applications WHERE id='app-1003'")}

    registered = {e["artifact_id"] for e in dpdp.lineage(p1)}

    hr("3. Lineage: everything Priya's data turned into")
    for e in dpdp.lineage(p1):
        print(f"  depth={e['depth']} {e['edge']:<9} {e['kind']:<12} store={e['store']:<13} {e['artifact_id']}")

    hr("4. Priya withdraws all consent and requests erasure: dry run")
    for purpose in APPLICANTS["app-1001"]["consents"]:
        dpdp.withdraw_consent(p1, purpose, erase=False)
    plan = dpdp.erase(p1, dry_run=True)
    for p in plan["plan"]:
        print(f"  {p['action']:<17} {p['kind']:<12} {p['store']:<13} <- {p['reason'][:70]}")
    try:
        with dpdp.context(p1, purpose="policy_issuance"):
            dpdp.protect("Can you also add critical illness cover? priya.sharma@example.in")
    except ConsentDenied as e:
        print(f"  further processing blocked: {e}")
        R["blocked"] = str(e)

    hr("5. Execute erasure")
    rahul_before = dpdp.vault.reveal(one(db, "SELECT body FROM applications WHERE id='app-1002'"))
    print("  Rahul's application BEFORE:", rahul_before)
    res = dpdp.erase(p1)
    print("  Rahul's application AFTER: ", dpdp.vault.reveal(one(db, "SELECT body FROM applications WHERE id='app-1002'")))
    print("  Portfolio summary AFTER:   ", one(db, "SELECT body FROM summaries WHERE id='PORTFOLIO-W45'")[:120])
    print("  Priya's application rows:  ", one(db, "SELECT count(*) FROM applications WHERE principal_id=?", p1))
    print("  Priya's KYC record rows:   ", one(db, "SELECT count(*) FROM kyc_records WHERE principal_id=?", p1),
          "(legal hold, sealed)")
    print("  Rogue cache row left:      ", one(db, "SELECT count(*) FROM cache WHERE id='K-rogue'"))
    print("  Eval rows left:            ", len((STATE / "evals" / "agent_golden.jsonl").read_text().splitlines()))
    print("  Her email token now reads: ", dpdp.vault.reveal(tok_email))

    hr("6. Erasure certificate")
    print(json.dumps({k: res[k] for k in ("request_id", "status", "artifacts_in_scope", "actions", "exceptions",
                                          "certificate_sha256")}, indent=2, default=str))
    print("  verification:")
    for v in res["verification"]:
        print(f"    {'OK ' if v['ok'] else 'FAIL'} {v['store']:<13} {v.get('note') or ''} {v['findings'][:2] if v['findings'] else ''}")

    hr("7. Evidence: manual step, reviewer sign-off, signed bundle and audit pack")
    rid = res["request_id"]
    # The contact-centre recordings have no connector (see inventory.yaml): an operator does it by hand.
    dpdp.record_manual_action(rid, "ops:meena", system="Contact-centre call recordings", action="deleted",
                              reference="CC-2026-1187", notes="Runbook CC-07 followed in the vendor console")
    try:
        dpdp.review(rid, "dpo:asha", decision="approved", notes="call 98765 43210 back")
    except Exception as e:  # noqa: BLE001 - shows the personal-data check
        print(f"  refused: {str(e)[:96]}...")
    rev = dpdp.review(rid, "dpo:asha", decision="approved", checklist={i.id: True for i in dpdp.config.evidence.review_checklist},
                      notes="KYC hold per sector regulation; escrow per Rule 8(3); recordings deleted by CC-2026-1187")
    print(f"  case log: manual action + review, sign-off {rev['sign_off']['state']}")
    ev_dir = STATE / "evidence"
    ev_dir.mkdir(exist_ok=True)
    bundle = dpdp.export_evidence(rid, str(ev_dir / f"{rid}.zip"))
    from dpdp_rights.evidence import verify_bundle
    from dpdp_rights.evidence.audit import default_period
    from dpdp_rights.evidence.render import case_html

    (ev_dir / "case.html").write_text(case_html(dpdp.case(rid)), encoding="utf-8")
    v = verify_bundle(bundle["path"])
    print(f"  evidence bundle {bundle['path']}: verified {v['ok']} (files, signature, certificate, case log)")
    start, end = default_period(1)
    pack = dpdp.export_audit_pack(start, end, str(ev_dir / "audit-pack.zip"))
    m = pack["report"]["metrics"]
    print(f"  audit pack {pack['path']}: {m['requests_received']} requests, {m['signed_off_pct']}% signed off, "
          f"{len(pack['report']['findings'])} findings")
    print(f"  open {ev_dir / 'case.html'} to read the case record")
    R["evidence"] = {"sign_off": rev["sign_off"], "bundle": bundle["path"], "verified": v["ok"],
                     "files": list(bundle["manifest"]["files"]), "fingerprint": bundle["manifest"]["key_fingerprint"],
                     "case_log": dpdp.cases.events(rid), "audit": m, "findings": pack["report"]["findings"]}

    hr("8. Rights desk: access, correction, nomination, grievance (Act ss.11-14)")
    from dpdp_rights.rights.access import access_html
    from dpdp_rights.rights.notice import notice_markdown, published_means

    rights_dir = STATE / "rights"
    rights_dir.mkdir(exist_ok=True)
    p2 = pids["app-1002"]
    acc = dpdp.rights.submit("access", p2, requested_by="service:mobile-app", verified_by="app-login",
                             verification_ref="sess-77a1", channel="Mobile app")
    print(f"  Rahul asks what we hold: case {acc['case_id']} is {acc['status']}, due {acc['due_by'][:10]}")
    dpdp.rights.decide(acc["case_id"], "dpo:asha", "approve")
    rep = dpdp.rights.access_report(acc["case_id"])
    (rights_dir / "access-report-rahul.html").write_text(access_html(rep), encoding="utf-8")
    print(f"  released: {', '.join(d['label'] for d in rep['data'])}; shared with "
          f"{', '.join(r['name'] for r in rep['recipients']) or 'nobody'}")
    upi_ref = next(v["ref"] for d in rep["data"] if d["type"] == "UPI_ID" for v in d["values"])
    cor = dpdp.rights.submit("correction", p2, requested_by="service:mobile-app", element_type="UPI_ID",
                             ref=upi_ref, new_value="rahul.verma@okicici", reason="Changed my UPI handle")
    dpdp.rights.decide(cor["case_id"], "dpo:asha", "approve")
    app_after = dpdp.vault.reveal(one(db, "SELECT body FROM applications WHERE id='app-1002'"))
    print(f"  correction applied through the vault; his application now reads: ...{app_after[-60:]}")
    nom = dpdp.rights.submit("nomination", p2, requested_by="service:mobile-app", nominee_name="Meera Verma",
                             nominee_contact="+91 98450 12345", relationship="sister", events="both")
    print(f"  nomination recorded: {dpdp.rights.view(nom['case_id'])['outcome']['nomination_id']} (death or incapacity)")
    grv = dpdp.rights.submit("grievance", p3, requested_by="service:contact-centre", channel="Contact centre",
                             category="consent", description="I withdrew marketing consent but got a renewal offer SMS")
    dpdp.rights.respond(grv["case_id"], "dpo:asha", "acknowledged", "We are checking the SMS campaign list")
    g = dpdp.rights.respond(grv["case_id"], "dpo:asha", "fulfilled",
                            "The SMS list was built before your withdrawal; removed under ticket MKT-311")
    print(f"  Anita's grievance {g['status']} within the {dpdp.rights.rules().due_days('grievance')}-day period; "
          f"log intact {g['integrity']['ok']}")
    (rights_dir / "notice.md").write_text(notice_markdown(published_means(dpdp)), encoding="utf-8")
    print(f"  Rule 14(1) notice for the website: {rights_dir / 'notice.md'}; access report: "
          f"{rights_dir / 'access-report-rahul.html'}")
    R["rights"] = {"cases": [dpdp.rights.view(c["case_id"]) for c in (acc, cor, nom, grv)],
                   "report": rep, "app_after": app_after, "rules": dpdp.rights.rules().ref()}

    if args.html:
        write_report(args.html, R, dpdp, db, p1, plan, res, registered, counts_before, rahul_before, tok_email)


# ---- HTML report -------------------------------------------------------------------------------------
NAMES = {ext: a["name"].split()[0] for ext, a in APPLICANTS.items()}
TABLES = {"applications": "Priya's application", "kyc_records": "Priya's KYC record",
          "audiences": "Priya's marketing audience entries", "chunks": "Embeddings in the vector index",
          "cache": "Agent cache entries", "summaries": "Underwriting notes and reports"}


REASON = {"default": "Held only for purposes she withdrew, and no law requires keeping it (default policy)",
          "Principal is only mentioned in another person's record":
              "This record belongs to someone else and only mentions her, so only her details are removed"}


def table_counts(db, pid) -> dict[str, int]:
    return {
        "applications": one(db, "SELECT count(*) FROM applications WHERE principal_id=?", pid),
        "kyc_records": one(db, "SELECT count(*) FROM kyc_records WHERE principal_id=?", pid),
        "audiences": one(db, "SELECT count(*) FROM audiences WHERE principal_id=?", pid),
        "chunks": one(db, "SELECT count(*) FROM chunks"),
        "cache": one(db, "SELECT count(*) FROM cache"),
        "summaries": one(db, "SELECT count(*) FROM summaries"),
        "eval": len((STATE / "evals" / "agent_golden.jsonl").read_text().splitlines()),
    }


def artifact_label(dpdp, aid: str) -> str:
    a = dpdp.store.get_artifact(aid)
    loc = str((a.locator or {}).get("id", "")) if a else ""
    if loc == "K-rogue":
        return "Unregistered cache row"
    if loc == "PORTFOLIO-W45":
        return "Weekly portfolio report"
    if loc == "KYC-1001":
        return "Priya's KYC record"
    if loc == "eval-001":
        return "Eval set row from Priya's chat"
    m = re.search(r"app-\d{4}", loc)
    who = NAMES.get(m.group(0), "?") if m else "?"
    prefix = loc.split("-", 1)[0]
    return {"app": f"{who}'s application", "C": f"Embedding of {who}'s application",
            "K": f"Agent reply cached for {who}", "UW": f"Underwriting note for {who}",
            "M": f"{who}'s cross-sell audience entry"}.get(prefix, f"{a.kind if a else 'item'} {loc}")


def write_report(path, R, dpdp, db, pid, plan, res, registered, counts_before, rahul_before, tok_email) -> None:
    from report import now, render

    actions = {p["artifact_id"]: p["action"] for p in plan["plan"]}
    R["plan"] = [{"label": artifact_label(dpdp, p["artifact_id"]), "store": p["store"], "action": p["action"],
                  "reason": REASON.get(p["reason"], p["reason"])} for p in plan["plan"]]
    R["graph"] = [{"artifact_id": e["artifact_id"], "label": artifact_label(dpdp, e["artifact_id"]),
                   "depth": e["depth"], "edge": e["edge"], "parents": e["parents"],
                   "action": actions.get(e["artifact_id"], "skip"),
                   "discovered": e["artifact_id"] not in registered}
                  for e in dpdp.lineage(pid)]
    R["consent_final"] = {"app-1003": {"marketing": "withdrawn"},
                          "app-1001": {p: "withdrawn" for p in APPLICANTS["app-1001"]["consents"]}}
    after = table_counts(db, pid)
    notes = {"applications": "deleted", "kyc_records": "kept: legal hold, sealed key",
             "audiences": "deleted", "chunks": "her embedding deleted; Rahul's redacted and re-embedded",
             "cache": "her entries and the unregistered row deleted", "summaries": "her note deleted, the weekly report rebuilt without her; Rahul's note redacted",
             "eval": "golden-set row deleted"}
    R["before_after"] = {
        "rahul_before": rahul_before,
        "rahul_spans": [(m.start(), m.end(), "EMAIL") for m in re.finditer(r"priya\.sharma@example\.in", rahul_before)],
        "rahul_after": dpdp.vault.reveal(one(db, "SELECT body FROM applications WHERE id='app-1002'")),
        "weekly_before": R["weekly_before"],
        "weekly_after": one(db, "SELECT body FROM summaries WHERE id='PORTFOLIO-W45'"),
        "counts": [{"what": TABLES.get(k, "Eval set rows from Priya's chats"), "before": counts_before[k],
                    "after": after[k], "note": notes[k]} for k in counts_before]
                  + [{"what": "Her email token, read by an application", "before": "priya.sharma@…",
                      "after": dpdp.vault.reveal(tok_email), "note": "her key destroyed (crypto-shredding)"}],
    }
    R["result"], R["generated"] = res, now()
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render(R), encoding="utf-8")
    print(f"\n  HTML report written to {out.resolve()}")


if __name__ == "__main__":
    main()
