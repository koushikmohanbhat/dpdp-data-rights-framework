"""End-to-end demo: a support copilot whose data spreads into tickets, vectors,
a semantic cache, an eval set, logs, a per-user summary and a weekly analytics
summary. Then one customer files an erasure request.

Runs fully offline (echo model, local vault, SQLite):

    python examples/support_copilot/demo.py            # clean run
    python examples/support_copilot/demo.py --leak     # simulate raw PII leaking into a log
    DPDP_PROVIDER=openai DPDP_MODEL=gpt-5-mini python examples/support_copilot/demo.py
    DPDP_PROVIDER=anthropic DPDP_MODEL=claude-sonnet-5-5 python examples/support_copilot/demo.py
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

from dpdp_erasure import EdgeType, ErasureKit  # noqa: E402
from dpdp_erasure.pii.detectors import verhoeff_check_digit  # noqa: E402

STATE = Path(".dpdp")
CFG = ROOT / "config" / "dpdp.local.yaml"


def fake_aadhaar(prefix: str) -> str:
    n = prefix + verhoeff_check_digit(prefix)
    return f"{n[:4]} {n[4:8]} {n[8:]}"


def setup_app_db() -> sqlite3.Connection:
    db = sqlite3.connect(STATE / "app.db")
    db.executescript("""
        CREATE TABLE tickets  (id TEXT PRIMARY KEY, principal_id TEXT, body TEXT);
        CREATE TABLE summaries(id TEXT PRIMARY KEY, body TEXT);
        CREATE TABLE chunks   (id TEXT PRIMARY KEY, chunk TEXT, embedding TEXT);
        CREATE TABLE cache    (id TEXT PRIMARY KEY, question TEXT, answer TEXT);
    """)
    return db


def hr(title: str) -> None:
    print(f"\n{'=' * 78}\n{title}\n{'=' * 78}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--leak", action="store_true", help="write one raw-PII log line that bypasses the SDK")
    args = ap.parse_args()

    shutil.rmtree(STATE, ignore_errors=True)
    STATE.mkdir()
    (STATE / "evals").mkdir()
    db = setup_app_db()
    kit = ErasureKit.from_yaml(str(CFG))

    log = logging.getLogger("copilot")
    log.setLevel(logging.INFO)
    fh = logging.FileHandler(STATE / "app.log")
    fh.setFormatter(logging.Formatter("%(asctime)s principal=%(dpdp_principal)s purpose=%(dpdp_purpose)s %(message)s"))
    fh.addFilter(kit.logging_filter())
    log.addHandler(fh)

    customers = {
        "cust-1001": ("Priya Sharma", "priya.sharma@example.in", "+91 98765 43210",
                      f"Hi, my name is Priya Sharma. I was charged twice for order 5521. My Aadhaar "
                      f"{fake_aadhaar('23456789012')} is linked. Call me on +91 98765 43210 or email priya.sharma@example.in."),
        "cust-1002": ("Rahul Verma", "rahul.v@example.in", "+91 91234 56789",
                      "My name is Rahul Verma. Refund for my wife's order hasn't arrived; her email is "
                      "priya.sharma@example.in. My UPI is rahulv@okhdfc."),
        "cust-1003": ("Anita Rao", "anita.rao@example.in", "+91 99887 76655",
                      "I am Anita Rao, PAN ABCPR1234K. The delivery partner was late for order 7781."),
        "cust-1004": ("Vikram Iyer", "vikram@example.in", "+91 90000 11111",
                      "This is Vikram Iyer. Charged twice on my card for order 9902, please reverse."),
    }

    hr("1. Customers onboard, grant purpose-specific consent, and raise tickets")
    ticket_arts: dict[str, str] = {}
    pids: dict[str, str] = {}
    for ext, (_name, email, phone, text) in customers.items():
        pid = kit.principal(ext)
        pids[ext] = pid
        kit.register_identifier(pid, "EMAIL", email)
        kit.register_identifier(pid, "PHONE_IN", phone)
        kit.grant_consent(pid, "support_resolution")
        kit.grant_consent(pid, "analytics")
        if ext == "cust-1001":
            kit.grant_consent(pid, "model_evaluation")

        with kit.context(pid, purpose="support_resolution", session_id=f"s-{ext}"):
            safe = kit.protect(text)
            tid = f"T-{ext[-4:]}"
            db.execute("INSERT INTO tickets VALUES (?,?,?)", (tid, pid, safe.text))
            t = kit.track_artifact("record", "tickets", {"id": tid}, element_ids=safe.element_ids, content=safe.text)
            ticket_arts[ext] = t.artifact_id
            log.info("ticket %s received: %s", tid, text)   # raw text in -> filter tokenises it

            vec = kit.embed([safe.text])[0]
            db.execute("INSERT INTO chunks VALUES (?,?,?)", (f"C-{tid}", safe.text, json.dumps(vec)))
            kit.track_artifact("embedding", "vectors", {"id": f"C-{tid}"}, parents=[t.artifact_id],
                               edge_type=EdgeType.EMBED, content=safe.text)

            ans = kit.generate(safe.text, system="You are a helpful bank support agent.", already_protected=True)
            db.execute("INSERT INTO cache VALUES (?,?,?)", (f"K-{tid}", safe.text[:60], ans.text))
            kit.track_artifact("cache_entry", "semantic_cache", {"id": f"K-{tid}"}, parents=[t.artifact_id],
                               content=ans.text)
        db.commit()
        print(f"  {ext} -> {pid}  ticket stored as: {safe.text[:90]}...")

    p1 = pids["cust-1001"]
    with kit.context(p1, purpose="model_evaluation"):
        row = {"id": "eval-001", "input": db.execute("SELECT body FROM tickets WHERE id='T-1001'").fetchone()[0],
               "ideal": "Apologise, confirm duplicate charge, initiate refund."}
        (STATE / "evals" / "support_golden.jsonl").write_text(json.dumps(row) + "\n")
        kit.track_artifact("eval_row", "eval_set", {"id": "eval-001"}, parents=[ticket_arts["cust-1001"]],
                           edge_type=EdgeType.COPY, content=row["input"])

    with kit.context(p1, purpose="support_resolution"):
        body = f"Customer profile summary: duplicate charge on order 5521; prefers phone contact. {db.execute('SELECT body FROM tickets WHERE id=?', ('T-1001',)).fetchone()[0][-60:]}"
        db.execute("INSERT INTO summaries VALUES ('S-user-1001', ?)", (body,))
        kit.track_artifact("summary", "summaries", {"id": "S-user-1001"}, parents=[ticket_arts["cust-1001"]],
                           edge_type=EdgeType.TRANSFORM, content=body)

    weekly = ("Weekly support trends: 2 duplicate-charge complaints (orders 5521, 9902), 1 refund delay, "
              "1 late delivery. Escalations: customer at <see ticket T-1001> threatened chargeback.")
    db.execute("INSERT INTO summaries VALUES ('S-weekly-W45', ?)", (weekly,))
    kit.track_artifact("summary", "summaries",
                       {"id": "S-weekly-W45",
                        "regen_instruction": "Write a weekly support-trends summary from these tickets. No names."},
                       parents=list(ticket_arts.values()), edge_type=EdgeType.AGGREGATE, purpose="analytics")

    # A cache row written by code that bypassed the SDK (never registered in lineage)
    tok_email = kit.vault.tokenize(p1, "EMAIL", "priya.sharma@example.in")
    db.execute("INSERT INTO cache VALUES ('K-rogue', 'refund status?', ?)", (f"Sent refund update to {tok_email}",))
    db.commit()
    if args.leak:
        with open(STATE / "app.log", "a") as f:
            f.write("2026-11-05 legacy-worker DEBUG callback to +91 98765 43210 failed\n")

    hr("2. Lineage graph for Priya (what her data turned into)")
    for e in kit.lineage(p1):
        print(f"  depth={e['depth']} {e['edge']:<9} {e['kind']:<12} store={e['store']:<15} {e['artifact_id']}")

    hr("3. Erasure request: dry run (plan only)")
    plan = kit.erase(p1, dry_run=True)
    for p in plan["plan"]:
        print(f"  {p['action']:<17} {p['kind']:<12} {p['store']:<15} <- {p['reason']}")

    hr("4. Execute erasure")
    print("  Rahul's ticket BEFORE:", kit.vault.reveal(db.execute("SELECT body FROM tickets WHERE id='T-1002'").fetchone()[0]))
    res = kit.erase(p1)
    print("  Rahul's ticket AFTER: ", kit.vault.reveal(db.execute("SELECT body FROM tickets WHERE id='T-1002'").fetchone()[0]))
    print("  Weekly summary AFTER: ", db.execute("SELECT body FROM summaries WHERE id='S-weekly-W45'").fetchone()[0][:160])
    print("  Priya ticket rows left:", db.execute("SELECT count(*) FROM tickets WHERE principal_id=?", (p1,)).fetchone()[0])
    print("  Rogue cache row left: ", db.execute("SELECT count(*) FROM cache WHERE id='K-rogue'").fetchone()[0])
    print("  Eval rows left:       ", len((STATE / "evals" / "support_golden.jsonl").read_text().splitlines()))
    print("  Token now reveals as: ", kit.vault.reveal(tok_email))

    hr("5. Erasure certificate")
    print(json.dumps({k: res[k] for k in ("request_id", "status", "artifacts_in_scope", "actions", "exceptions",
                                          "vault", "certificate_sha256")}, indent=2, default=str))
    print("  verification:")
    for v in res["verification"]:
        print(f"    {'OK ' if v['ok'] else 'FAIL'} {v['store']:<15} {v.get('note') or ''} {v['findings'][:2] if v['findings'] else ''}")


if __name__ == "__main__":
    main()
