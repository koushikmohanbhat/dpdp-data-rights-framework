"""Access report (Act s.11): what personal data is processed, for what, where, and who it was shared with.

The report is built from the vault (which values exist), the lineage graph (where they went and what
was derived from them), the consent ledger and purposes (why), and ``rights.recipients`` (other Data
Fiduciaries and Data Processors). It is stored with vault tokens only and revealed when delivered:
``masked`` (default), ``full`` or ``none`` (types and counts only). After erasure every value reads
[ERASED].
"""
from __future__ import annotations

import html
from collections import defaultdict

from ..core.models import utcnow
from ..evidence.case import iso

# Plain-language names for where data lives, by artifact kind.
PLACES = {
    "prompt": "Conversations with our AI assistant", "completion": "Conversations with our AI assistant",
    "log": "System logs", "trace": "System monitoring traces", "embedding": "Search index used by the assistant",
    "cache_entry": "Saved assistant answers", "eval_row": "Datasets used to test the assistant's quality",
    "finetune_row": "Datasets used to train AI models", "model": "AI models trained with data",
    "summary": "Summaries and reports", "memory_event": "Assistant memory (current conversations)",
    "memory_record": "Assistant memory (long-term)", "kb_document": "Knowledge-base documents",
    "provider_response": "Data held by our AI model provider", "provider_file": "Files held by our AI model provider",
    "record": "Records in our systems",
}
TYPES = {
    "EMAIL": "Email address", "PHONE_IN": "Mobile number", "PHONE": "Phone number", "AADHAAR": "Aadhaar number",
    "PAN": "PAN", "NAME": "Name", "ADDRESS": "Address", "UPI_ID": "UPI ID", "CARD_NUMBER": "Card number",
    "BANK_ACCOUNT": "Bank account number", "VEHICLE_REG": "Vehicle registration number", "GSTIN": "GSTIN",
    "ABHA_NUMBER": "ABHA number", "DRIVING_LICENCE": "Driving licence number", "VOTER_ID": "Voter ID",
    "PASSPORT": "Passport number", "DATE": "Date", "FREE_TEXT": "Other details you told us",
    "EXTERNAL_ID": "Customer identifier", "RIGHTS_NOTE": "Messages you sent us about your data rights",
}
EXTERNAL_PREFIXES = ("aws_", "gcp_", "openai", "anthropic", "langfuse")


def label(etype: str) -> str:
    return TYPES.get(etype, etype.replace("_", " ").title())


def build_access_report(dpdp, pid: str, rs) -> tuple[dict, list[str]]:
    """Returns (report with tokens only, notes for the reviewer)."""
    store, vault = dpdp.store, dpdp.vault
    notes: list[str] = []
    values: dict[str, list[str]] = defaultdict(list)
    for t in vault.tokens_for(pid):
        values[vault.element_type_of(t) or "FREE_TEXT"].append(t)

    places: dict[str, dict] = {}
    by_store_types: dict[str, set[str]] = defaultdict(set)
    purposes_used: set[str] = set()
    for e in store.downstream(pid):
        a = e["artifact"]
        if a.status == "erased":
            continue
        key = PLACES.get(a.kind, a.kind.replace("_", " ").capitalize())
        p = places.setdefault(key, {"place": key, "items": 0, "derived": 0, "purposes": set(), "kept_under_law": 0})
        p["items"] += 1
        if e["edge_type"]:
            p["derived"] += 1
        if a.status == "retained":
            p["kept_under_law"] += 1
        if a.purpose_id:
            p["purposes"].add(a.purpose_id)
            purposes_used.add(a.purpose_id)
        for tok in store.tokens_in_artifact_for(a.artifact_id, pid):
            by_store_types[a.store].add(vault.element_type_of(tok) or "FREE_TEXT")
        by_store_types[a.store].add("__any__")

    consents = store.consents_for(pid)
    purpose_rows = []
    for pid_ in sorted({c["purpose_id"] for c in consents} | purposes_used):
        pur = store.get_purpose(pid_)
        cs = [c for c in consents if c["purpose_id"] == pid_]
        status = ("given" if any(c["status"] == "granted" for c in cs) else "withdrawn") if cs else None
        purpose_rows.append({
            "purpose": pid_, "description": pur.description if pur else "",
            "basis": (pur.legal_basis if pur else "consent"),
            "consent": status,
            "consent_given_at": iso(min((c["granted_at"] for c in cs), default=None)) if cs else None,
            "withdrawn_at": iso(max((c["withdrawn_at"] for c in cs if c["withdrawn_at"]), default=None)) if cs else None,
            "notice_version": max((c["notice_version"] or "" for c in cs), default=None) or None,
            "kept_under_law": (pur.legal_hold_basis if pur and pur.legal_hold_basis else None),
        })

    recipients, withheld = [], 0
    known = {r.store: r for r in dpdp.config.rights.recipients}
    for st, types in sorted(by_store_types.items()):
        r = known.get(st)
        if r is None:
            ctype = getattr(dpdp.connectors.get(st), "type_name", "") or ""
            if ctype.startswith(EXTERNAL_PREFIXES):
                notes.append(f"store '{st}' ({ctype}) holds this person's data but has no rights.recipients entry: "
                             "if it is a Data Processor or another Data Fiduciary, add it (s.11(1)(b))")
            continue
        if r.exempt_from_access:
            withheld += 1
            notes.append(f"recipient '{r.name}' withheld under {r.exemption_basis or 's.11(2)'}")
            continue
        recipients.append({"name": r.name, "role": r.role, "description": r.description,
                           "data_shared": sorted(label(t) for t in types if t != "__any__") or ["Details you gave us"]})
    if not dpdp.config.rights.recipients:
        notes.append("rights.recipients is empty: the report lists no Data Processors or other Data Fiduciaries")

    rights = {k: {"summary": v.get("summary"), "basis": v.get("basis"), "respond_within_days": v.get("respond_within_days")}
              for k, v in rs.data["requests"].items() if k != "nominee_invocation"}
    report = {
        "schema": "dpdp-rights/access-report/v1",
        "generated_at": utcnow().isoformat(),
        "principal_id": pid,
        "data": [{"type": t, "label": label(t), "refs": sorted(toks)} for t, toks in sorted(values.items())],
        "places": [p | {"purposes": sorted(p["purposes"])} for p in sorted(places.values(), key=lambda x: x["place"])],
        "purposes": purpose_rows,
        "recipients": recipients,
        "nominations": len([n for n in store.nominations_for(pid) if n["status"] != "revoked"]),
        "your_rights": rights,
        "board_escalation": rs.data.get("board_escalation"),
        "contact": dpdp.config.rights.contact,
        "rules": rs.ref(),
    }
    if withheld:
        report["_withheld_recipients"] = withheld      # internal; removed before delivery
    return report, notes


def render_values(vault, report: dict, pid: str, mode: str) -> dict:
    """The report as delivered: values masked, full or left out; internal fields removed."""
    out = {k: v for k, v in report.items() if not k.startswith("_")}
    data = []
    for d in report["data"]:
        row = {"type": d["type"], "label": d["label"], "count": len(d["refs"])}
        if mode != "none":
            row["values"] = [{"ref": r, "value": _value(vault, r, pid, mode)} for r in d["refs"]]
        data.append(row)
    out["data"], out["values_shown"] = data, mode
    return out


def _value(vault, ref: str, pid: str, mode: str) -> str:
    from ..vault.vault import ERASED_MARKER

    v = vault.reveal(ref, {pid}, masked=(mode == "masked"))
    return ERASED_MARKER if v == ref else v      # sealed (escrow / hold) or erased: not readable here


def access_html(rep: dict) -> str:
    e = html.escape

    def table(head, rows, empty="None"):
        if not rows:
            return f"<p class=muted>{e(empty)}</p>"
        return ("<table><thead><tr>" + "".join(f"<th>{e(h)}</th>" for h in head) + "</tr></thead><tbody>"
                + "".join("<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>" for r in rows) + "</tbody></table>")

    data_rows = []
    for d in rep["data"]:
        vals = "<br>".join(f"{e(v['value'])} <span class=muted>ref {e(v['ref'])}</span>" for v in d.get("values", []))
        data_rows.append([e(d["label"]), str(d["count"]), vals or "<span class=muted>not shown</span>"])
    place_rows = [[e(p["place"]), str(p["items"]), str(p["derived"]), e(", ".join(p["purposes"]) or "—"),
                   str(p["kept_under_law"])] for p in rep["places"]]
    pur_rows = [[e(p["purpose"]), e(p["description"] or ""),
                 e("Legitimate use (no consent needed)" if p["basis"] == "legitimate_use" else "Your consent"),
                 e(p["consent"] or "—"), e((p["consent_given_at"] or "—")[:10]), e((p["withdrawn_at"] or "—")[:10]),
                 e(p["kept_under_law"] or "—")] for p in rep["purposes"]]
    rec_rows = [[e(r["name"]), e("Processes data for us" if r["role"] == "processor" else "Another organisation deciding how to use it"),
                 e(r["description"]), e(", ".join(r["data_shared"]))] for r in rep["recipients"]]
    right_rows = [[e(k.replace("_", " ").capitalize()), e(v["summary"] or ""), f"{v['respond_within_days']} days",
                   e(v["basis"] or "")] for k, v in rep["your_rights"].items()]
    css = ("body{font-family:system-ui,sans-serif;margin:0;background:#f7f7f5;color:#1f2430}main{max-width:900px;margin:0 auto;"
           "padding:32px 20px 60px}h1{font-size:24px;margin:0 0 6px}h2{font-size:17px;margin:30px 0 10px}"
           "table{width:100%;border-collapse:collapse;background:#fff;border:1px solid #e1e1dc;font-size:14px}"
           "th,td{padding:8px 10px;border-bottom:1px solid #eee;text-align:left;vertical-align:top}th{background:#f0f0ec}"
           ".muted{color:#6b7280;font-size:12px}p{line-height:1.5}")
    return (f"<!DOCTYPE html><html lang=en><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
            f"<title>Your personal data</title><style>{css}</style></head><body><main>"
            f"<h1>Your personal data with us</h1><p class=muted>Prepared {e(rep['generated_at'][:10])} under "
            f"{e(rep['rules']['rule_set'])} {e(rep['rules']['rule_version'])}. Values shown: {e(rep['values_shown'])}.</p>"
            "<h2>What we hold</h2>" + table(["Kind of data", "How many", "Values"], data_rows) +
            "<h2>Where it is and what we made from it</h2><p>“Derived” items were created from your data, such as summaries "
            "or search-index entries. “Kept under law” items are retained because a law requires it.</p>"
            + table(["Where", "Items", "Derived", "Purposes", "Kept under law"], place_rows) +
            "<h2>Why we process it</h2>" + table(["Purpose", "What it is", "Basis", "Consent", "Given", "Withdrawn",
                                                  "Law requiring us to keep it"], pur_rows) +
            "<h2>Who we shared it with</h2>" + table(["Organisation", "Role", "What they do", "Data shared"], rec_rows,
                                                     "We have not shared your data with other organisations.") +
            ("<p class=muted>Where we replace your details with a coded reference before storing or sharing them, the "
             "organisation holds that reference, not the value itself.</p>" if rec_rows else "") +
            "<h2>Your rights and how fast we respond</h2>" + table(["Right", "What it means", "We respond within", "Law"], right_rows) +
            (f"<p><b>Contact:</b> {e(rep['contact'])}</p>" if rep.get("contact") else "") +
            (f"<p>{e(rep['board_escalation'])}</p>" if rep.get("board_escalation") else "") +
            "</main></body></html>")
