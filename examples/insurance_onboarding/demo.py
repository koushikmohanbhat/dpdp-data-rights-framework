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
    DPDP_PROVIDER=openai DPDP_MODEL=gpt-5-mini python examples/insurance_onboarding/demo.py
    DPDP_PROVIDER=anthropic DPDP_MODEL=claude-sonnet-5-5 python examples/insurance_onboarding/demo.py
"""
from __future__ import annotations

import argparse
import json
import logging
import shutil
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

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
        product="term life", email="priya.sharma@example.in", phone="+91 98765 43210",
        consents=["policy_issuance", "analytics", "marketing", "model_improvement"],
        text=(f"My name is Priya Sharma. I want a 1 crore term plan. Aadhaar {fake_aadhaar('23456789012')}, "
              "PAN ABCPS1234K. Reach me on +91 98765 43210 or priya.sharma@example.in. Non-smoker, age 34.")),
    "app-1002": dict(
        product="motor", email="rahul.v@example.in", phone="+91 91234 56789",
        consents=["policy_issuance", "analytics", "marketing"],
        text=("My name is Rahul Verma. Comprehensive cover for KA-01-AB-1234. Nominee is my wife, "
              "email priya.sharma@example.in. Premium via UPI rahulv@okhdfc.")),
    "app-1003": dict(
        product="health", email="anita.rao@example.in", phone="+91 99887 76655",
        consents=["policy_issuance", "analytics", "marketing"],
        text="I am Anita Rao, PAN ABCPR1234K. Family floater for 2 adults, 1 child. No pre-existing conditions."),
    "app-1004": dict(
        product="travel", email="vikram@example.in", phone="+91 90000 11111",
        consents=["policy_issuance", "analytics"],
        text="This is Vikram Iyer. Schengen travel cover, 12 days in December. Pay by card 4111 1111 1111 1111."),
}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--leak", action="store_true", help="a legacy job writes a raw phone number to the log")
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

    hr("2. Anita withdraws consent for marketing only")
    p3 = pids["app-1003"]
    out = dpdp.withdraw_consent(p3, "marketing")
    print(f"  consents withdrawn: {out['withdrawn']}; actions: {out['erasure']['actions']}")
    print("  Anita's audience row left:", one(db, "SELECT count(*) FROM audiences WHERE id='M-app-1003'"))
    print("  Anita's application left: ", one(db, "SELECT count(*) FROM applications WHERE id='app-1003'"),
          "(policy issuance consent still active)")

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

    hr("5. Execute erasure")
    print("  Rahul's application BEFORE:", dpdp.vault.reveal(one(db, "SELECT body FROM applications WHERE id='app-1002'")))
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


if __name__ == "__main__":
    main()
