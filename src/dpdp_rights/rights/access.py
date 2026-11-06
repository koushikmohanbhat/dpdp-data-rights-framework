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


STATUS_TEXT = {
    "complete": "We searched every system on our register of systems that hold personal data for this request, "
                "and each search was working and recently tested. This report covers all of them.",
    "configured_coverage": "Every system on our register is connected to our data-rights tools, but they were not "
                           "searched for this request. This report shows what our records show.",
    "partial": "This report is partial. Some systems on our register were checked by hand, could not be "
               "searched, or are not searched automatically; they are listed below.",
    "coverage_unknown": "We could not confirm that this report covers every system that may hold your data. "
                        "It shows what our records show; other systems may hold data about you.",
}


def completeness(dpdp, unconfirmed_stores: list[str], search: dict[str, dict] | None = None,
                 today=None) -> tuple[dict, list[str]]:
    """How complete the report is, judged against the deployment inventory (rights.inventory_path).

    complete             every in-scope system on the inventory was searched for THIS request (native discovery ran
                         and succeeded), its actions were tested end to end within the retest window, and every
                         external store holding this person's data has a recipient entry
    configured_coverage  as complete, except that no search ran for this request (rights.access_search is off)
    partial              anything else: systems checked by hand, not searched, searched only through tracked
                         records, whose search failed, or whose actions are untested or overdue for a retest;
                         or recipients unconfirmed
    coverage_unknown     no inventory configured (or it cannot be read): nothing to compare the report against

    Connector configuration alone never makes a report complete.
    """
    notes: list[str] = []
    out = {"status": "coverage_unknown", "searched": [], "from_records": [], "search_failed": [],
           "not_tested": [], "checked_by_hand": [], "not_searched": [],
           "unconfirmed_recipients": len(unconfirmed_stores), "search_ran": search is not None, "basis": None}
    path = dpdp.config.rights.inventory_path
    if not path:
        notes.append("rights.inventory_path is not set: the report is marked 'coverage unknown' for the principal")
        return out, notes
    try:
        from ..delivery.inventory import RETEST_DAYS, Inventory, coverage_report

        inv = Inventory.load(path)
        rows = coverage_report(inv, dpdp.config, today=today)["systems"]
    except Exception as e:  # noqa: BLE001
        notes.append(f"inventory {path} could not be read ({type(e).__name__}): report marked 'coverage unknown'")
        return out, notes
    configured_only = []
    for r in rows:
        name = r["system"]
        if r["status"] in ("automated", "automated_with_limits"):
            if not r["tested"]:
                out["not_tested"].append(name)
            if search is None:
                configured_only.append(name)
            elif r["discover"] == "lineage":
                out["from_records"].append(name)       # the connector cannot search; only tracked items are known
            elif not (search.get(r["connector"]) or {}).get("ok"):
                out["search_failed"].append(name)
            else:
                out["searched"].append(name)
        elif r["status"] == "manual":
            out["checked_by_hand"].append(name)
            if not r["tested"]:
                out["not_tested"].append(name)
        elif r["status"] == "gap":
            out["not_searched"].append(name)
    out["basis"] = {"register": inv.engagement.system or inv.engagement.client,
                    "prepared_on": str(inv.engagement.prepared_on) if inv.engagement.prepared_on else None,
                    "systems": sum(r["status"] != "out_of_scope" for r in rows), "retest_days": RETEST_DAYS}
    if configured_only:
        out["configured_only"] = configured_only
    partial = any(out[k] for k in ("from_records", "search_failed", "not_tested", "checked_by_hand",
                                   "not_searched")) or unconfirmed_stores
    out["status"] = "partial" if partial else ("configured_coverage" if search is None else "complete")
    if search is None:
        notes.append("rights.access_search is off: no system was searched for this request, so the report can say "
                     "at most 'configured coverage'")
    if out["checked_by_hand"]:
        notes.append("check by hand before release, and say what you found in the approval note: "
                     + ", ".join(out["checked_by_hand"]))
    if out["search_failed"]:
        notes.append("search failed for this request; check by hand or re-run: " + ", ".join(out["search_failed"]))
    if out["from_records"]:
        notes.append("not searched (the connector acts only on tracked items); reported from records: "
                     + ", ".join(out["from_records"]))
    if out["not_tested"]:
        notes.append(f"actions not tested end to end in the last {RETEST_DAYS} days (inventory tested_on): "
                     + ", ".join(out["not_tested"]))
    if out["not_searched"]:
        notes.append("not searched (no connector, no manual procedure): " + ", ".join(out["not_searched"]))
    return out, notes


def label(etype: str) -> str:
    return TYPES.get(etype, etype.replace("_", " ").title())


def build_access_report(dpdp, pid: str, rs) -> tuple[dict, list[str]]:
    """Returns (report with tokens only, notes for the reviewer)."""
    store, vault = dpdp.store, dpdp.vault
    notes: list[str] = []
    search = None
    if dpdp.config.rights.access_search:
        # Search every connected system now, so the report rests on this request's results, not on configuration.
        # New hits are added to lineage and appear in the report below.
        from ..connectors.base import ErasureContext

        ctx = ErasureContext(pid, vault.tokens_for(pid), vault.snapshot_values(pid), dry_run=True)
        search, _ = dpdp.orchestrator.search(ctx)
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

    recipients, withheld, unconfirmed = [], 0, []
    known = {r.store: r for r in dpdp.config.rights.recipients}
    for st, types in sorted(by_store_types.items()):
        r = known.get(st)
        if r is None:
            ctype = getattr(dpdp.connectors.get(st), "type_name", "") or ""
            if ctype.startswith(EXTERNAL_PREFIXES):
                unconfirmed.append(st)
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

    complete, cnotes = completeness(dpdp, unconfirmed, search)
    notes.extend(cnotes)
    complete["summary"] = STATUS_TEXT[complete["status"]]
    rights = {k: {"summary": v.get("summary"), "basis": v.get("basis"), "respond_within_days": v.get("respond_within_days")}
              for k, v in rs.data["requests"].items() if k != "nominee_invocation"}
    report = {
        "schema": "dpdp-rights/access-report/v1",
        "generated_at": utcnow().isoformat(),
        "principal_id": pid,
        "completeness": complete,
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


def _banner(c: dict | None) -> str:
    """Completeness, shown first and prominently, so a partial report is never read as a complete one."""
    if not c:
        c = {"status": "coverage_unknown", "summary": STATUS_TEXT["coverage_unknown"]}
    e = html.escape
    colour = {"complete": ("#e7f6ec", "#11733b", "Complete"), "partial": ("#fdf0d5", "#9a5b00", "Partial"),
              "configured_coverage": ("#fdf0d5", "#9a5b00", "Configured coverage (not searched for this request)"),
              "coverage_unknown": ("#fde3e1", "#b42318", "Coverage unknown")}[c["status"]]
    parts = [f"<div style='background:{colour[0]};border-left:6px solid {colour[1]};padding:14px 18px;margin:18px 0;"
             f"border-radius:6px'><div style='font-weight:700;color:{colour[1]};font-size:16px'>Completeness: "
             f"{colour[2]}</div><p style='margin:6px 0'>{e(c['summary'])}</p>"]
    if c.get("checked_by_hand"):
        parts.append("<p style='margin:6px 0'><b>Checked by hand (not in the tables below):</b> " + e(", ".join(c["checked_by_hand"])) + "</p>")
    for key, text in (("search_failed", "Search failed for this request"),
                      ("from_records", "Not searched; shown from our records only"),
                      ("not_tested", "Not tested recently"),
                      ("not_searched", "Not searched")):
        if c.get(key):
            parts.append(f"<p style='margin:6px 0'><b>{text}:</b> " + e(", ".join(c[key])) + "</p>")
    if c.get("unconfirmed_recipients"):
        parts.append(f"<p style='margin:6px 0'><b>Sharing not yet confirmed</b> for {c['unconfirmed_recipients']} "
                     "system(s) that hold your data.</p>")
    if c.get("reviewer_note"):
        parts.append("<p style='margin:6px 0'><b>Our reviewer's note:</b> " + e(c["reviewer_note"]) + "</p>")
    if c.get("basis"):
        b = c["basis"]
        searched = (f" Searched for this request: {len(c.get('searched') or [])} of {b['systems']}."
                    if c.get("search_ran") else "")
        parts.append(f"<p class=muted style='margin:6px 0'>Compared with our register of {b['systems']} systems"
                     + (f" (updated {e(b['prepared_on'])})" if b.get("prepared_on") else "") + "." + searched + "</p>")
    return "".join(parts) + "</div>"


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
            + _banner(rep.get("completeness")) +
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
