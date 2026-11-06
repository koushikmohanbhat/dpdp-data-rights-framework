"""Audit pack for a period: what was asked, what was done, how fast, who signed off, and whether
the evidence is intact. Offline; reads only the control-plane database (and an inventory, if given).
"""
from __future__ import annotations

import hashlib
import json
import statistics
from datetime import datetime, timedelta, timezone

from ..core.models import utcnow
from .bundle import write_signed_zip
from .case import TERMINAL, aware, build_case, iso
from .render import audit_html, audit_markdown


def parse_day(s: str) -> datetime:
    return datetime.fromisoformat(s).replace(tzinfo=timezone.utc) if len(s) == 10 else aware(datetime.fromisoformat(s))


def check_certificate_chain(store, signer=None) -> dict:
    """Walk every certificate in issue order: hash, link to the previous one, signature."""
    from ..security.signing import unb64, verify_with_public_key

    pem = None
    if signer is not None and hasattr(signer, "public_key_pem"):
        try:
            pem = signer.public_key_pem()
        except Exception:  # noqa: BLE001
            pem = None
    certs = store.all_certificates()
    out = {"certificates": len(certs), "hash_ok": True, "links_ok": True, "signatures_ok": None, "first_break": None}
    prev, sigs = None, []
    for c in certs:
        digest = hashlib.sha256(c["payload"].encode()).digest()
        body = json.loads(c["payload"])
        h_ok = digest.hex() == c["sha256"]
        l_ok = c["prev_sha256"] == prev and body.get("prev_certificate_sha256") == prev
        if not h_ok:
            out["hash_ok"] = False
        if not l_ok:
            out["links_ok"] = False
        if (not h_ok or not l_ok) and out["first_break"] is None:
            out["first_break"] = c["seq"]
        if c["signature"]:
            if pem:
                sigs.append(verify_with_public_key(pem, digest, unb64(c["signature"])))
            elif signer is not None:
                sigs.append(signer.verify(digest, unb64(c["signature"])))
        prev = c["sha256"]
    if sigs:
        out["signatures_ok"] = all(sigs)
    return out


def _pct(n: int, d: int):
    return round(100 * n / d, 1) if d else None


def audit_pack(dpdp, start: datetime, end: datetime, inventory=None) -> dict:
    """Build the audit report for requests received in [start, end). Dry runs are excluded."""
    cfg = dpdp.config.evidence
    store = dpdp.store
    now = utcnow()
    reqs = [r for r in store.requests_between(start, end) if not r.get("dry_run")]
    findings: list[dict] = []

    def find(level, code, message, request_id=None):
        findings.append({"level": level, "code": code, "message": message, "request_id": request_id})

    rows, cases, days = [], {}, []
    by_status: dict[str, int] = {}
    by_scope = {"full": 0, "purpose": 0}
    by_channel: dict[str, int] = {}
    sign = {"approved": 0, "pending": 0, "needs_info": 0, "rejected": 0, "not_required": 0, "not_reviewable": 0}
    within = finished = 0
    for r in reqs:
        rid = r["request_id"]
        case = build_case(dpdp, rid)
        cases[rid] = case
        s, so = case["sla"], case["sign_off"]
        by_status[r["status"]] = by_status.get(r["status"], 0) + 1
        by_scope["full" if r["scope"] == "full" else "purpose"] += 1
        ch = (r["requested_via"] or "unknown").removesuffix("-withdrawal")
        by_channel[ch] = by_channel.get(ch, 0) + 1
        sign[so["state"]] = sign.get(so["state"], 0) + 1
        if s["days_taken"] is not None:
            days.append(s["days_taken"])
        if r["status"] in TERMINAL:
            finished += 1
            within += 1 if s["met"] else 0
        rows.append({"request_id": rid, "scope": r["scope"], "status": r["status"], "received_at": s["received_at"],
                     "days_taken": s["days_taken"], "sla_met": s["met"], "sign_off": so["state"]})
        if s["open_overdue"]:
            find("error", "overdue", f"open past its due date ({s['due_by']})", rid)
        if s["met"] is False:
            find("warning", "sla_missed", f"completed after its due date ({s['days_taken']} days)", rid)
        if r["status"] == "failed":
            find("warning", "failed", "request failed; re-run it or record why it cannot be completed", rid)
        if not case["case_log_check"]["ok"]:
            find("error", "case_log_broken", f"case log broken at {case['case_log_check']['broken_at']}", rid)
        cert = case["certificate"]
        if cert and not (cert["check"]["hash_ok"] and cert["check"]["chain_ok"]):
            find("error", "certificate_invalid", "certificate hash or chain link does not verify", rid)
        if cert and cert["check"].get("signature_ok") is False:
            find("error", "certificate_signature_invalid", "certificate signature does not verify", rid)
        if so["state"] in ("rejected", "needs_info"):
            find("warning", f"review_{so['state']}", f"reviewer decision is {so['state']}", rid)
        if r["status"] == "completed_with_exceptions" and so["state"] not in ("approved", "not_required"):
            find("warning", "exceptions_unreviewed", "completed with exceptions and not signed off", rid)
        elif so["state"] == "pending" and s["completed_at"]:
            age = (now - aware(datetime.fromisoformat(s["completed_at"]))).days
            if age > cfg.sign_off_due_days:
                find("warning", "sign_off_overdue", f"awaiting sign-off for {age} days", rid)
        if so.get("stale_approvals"):
            find("warning", "stale_approval", "approval was given before a later manual action; review again", rid)

    chain = check_certificate_chain(store, dpdp.orchestrator.signer)
    if not chain["hash_ok"] or not chain["links_ok"]:
        find("error", "certificate_chain_broken", f"certificate chain breaks at seq {chain['first_break']}")
    if chain["signatures_ok"] is False:
        find("error", "certificate_chain_signature", "one or more certificate signatures do not verify")
    if dpdp.orchestrator.signer is None:
        find("warning", "unsigned", "certificates and case events are not signed (certificates.signer: none)")

    grants = [g for g in store.grants() if start <= aware(g["created_at"]) < end]
    logs = [x for x in store.access_logs() if start <= aware(x["at"]) < end]
    escrows = store.escrows()
    overdue = [e for e in escrows if e["status"] == "sealed" and aware(e["purge_after"]) <= now]
    for e in overdue:
        find("warning", "escrow_purge_overdue", f"escrow {e['escrow_id']} passed its purge date; run purge-escrows",
             e.get("request_id"))

    rights = rights_summary(dpdp, start, end)
    for c in rights["overdue"]:
        find("error", "rights_overdue", f"{c['type']} case open past its due date ({c['due_by']})", c["case_id"])
    for c in rights["late"]:
        find("warning", "rights_late", f"{c['type']} case closed after its due date", c["case_id"])
    for c in rights["chain_broken"]:
        find("error", "rights_log_broken", "rights case event log does not verify", c)

    coverage = None
    if inventory is not None:
        from ..delivery.inventory import coverage_report

        coverage = coverage_report(inventory, dpdp.config)
        if coverage["summary"]["errors"]:
            find("warning", "coverage_errors", f"{coverage['summary']['errors']} coverage errors in the inventory")

    days_sorted = sorted(days)
    order = {"error": 0, "warning": 1, "info": 2}
    findings.sort(key=lambda f: (order[f["level"]], f["code"]))
    return {
        "schema": "dpdp-rights/audit-pack/v1",
        "period": {"from": iso(start), "to": iso(end)},
        "generated_at": now.isoformat(),
        "environment": dpdp.config.environment,
        "tenant": dpdp.config.tenant,
        "metrics": {
            "requests_received": len(reqs),
            "finished": finished,
            "completed_within_sla_pct": _pct(within, finished),
            "median_days": round(statistics.median(days_sorted), 2) if days_sorted else None,
            "p95_days": days_sorted[min(len(days_sorted) - 1, int(0.95 * len(days_sorted)))] if days_sorted else None,
            "signed_off_pct": _pct(sign["approved"], finished - sign["not_required"]) if finished else None,
            "required_approvals": cfg.required_approvals,
            "by_status": by_status, "by_scope": by_scope, "by_channel": by_channel,
            "sign_off": {k: v for k, v in sign.items() if v},
        },
        "certificate_chain": chain,
        "break_glass": {"grants": len(grants), "approved": sum(1 for g in grants if g["approved_by"]),
                        "reads_allowed": sum(1 for x in logs if x["outcome"] == "allowed"),
                        "reads_denied": sum(1 for x in logs if x["outcome"] == "denied")},
        "escrow": {"sealed": sum(1 for e in escrows if e["status"] == "sealed"),
                   "purged": sum(1 for e in escrows if e["status"] == "purged"), "purge_overdue": len(overdue)},
        "rights": {k: v for k, v in rights.items() if k not in ("overdue", "late", "chain_broken")},
        "findings": findings,
        "requests": rows,
        "coverage": coverage,
        "_cases": cases,
    }


def rights_summary(dpdp, start: datetime, end: datetime) -> dict:
    """Rights cases received in the period, by type: received, closed, within due date, open, overdue."""
    from ..rights.desk import CLOSED

    by_type: dict[str, dict] = {}
    overdue, late, broken = [], [], []
    for c in dpdp.rights.list(start=start, end=end):
        b = by_type.setdefault(c["type"], {"received": 0, "fulfilled": 0, "rejected": 0, "failed": 0, "open": 0,
                                           "within_due": 0, "closed": 0})
        b["received"] += 1
        if c["status"] in CLOSED:
            b[c["status"]] += 1
            b["closed"] += 1
            b["within_due"] += 1 if c["within_due"] else 0
            if c["within_due"] is False:
                late.append(c)
        else:
            b["open"] += 1
        if c["overdue"]:
            overdue.append(c)
        if not dpdp.rights.verify_chain(c["case_id"])["ok"]:
            broken.append(c["case_id"])
    for b in by_type.values():
        b["within_due_pct"] = _pct(b["within_due"], b["closed"])
    return {"by_type": by_type, "overdue_count": len(overdue), "overdue": overdue, "late": late,
            "chain_broken": broken}


def export_audit_pack(dpdp, start: datetime, end: datetime, path: str | None = None, inventory=None,
                      include_cases: bool = True) -> dict:
    rep = audit_pack(dpdp, start, end, inventory)
    cases = rep.pop("_cases")
    files = {"audit.json": json.dumps(rep, indent=2, default=str, ensure_ascii=False).encode(),
             "audit.md": audit_markdown(rep).encode(),
             "audit.html": audit_html(rep).encode()}
    if include_cases:
        for rid, c in cases.items():
            files[f"cases/{rid}.json"] = json.dumps(c, indent=2, default=str, ensure_ascii=False).encode()
    data, manifest = write_signed_zip(path, files, {"schema": "dpdp-rights/evidence-bundle/v1", "kind": "audit_pack",
                                                    "period": rep["period"],
                                                    "findings": {lvl: sum(1 for f in rep["findings"] if f["level"] == lvl)
                                                                 for lvl in ("error", "warning")}},
                                      dpdp.orchestrator.signer)
    return {"path": path, "bytes": len(data), "report": rep, "manifest": manifest, "data": data if path is None else None}


def default_period(days: int = 90) -> tuple[datetime, datetime]:
    end = utcnow() + timedelta(seconds=1)
    return end - timedelta(days=days), end
