"""Drafts of the Rule 7 intimations, built from an assessment. Facts the framework knows are filled in; everything
else is a visible ``[DPO: ...]`` placeholder. Drafts contain pseudonymous ids and categories of data only, never
values, so they can be reviewed and circulated before anyone resolves contacts through the vault."""
from __future__ import annotations

from ..rights.access import label
from .desk import EXPOSURE

TODO = "[DPO: {}]"


def _n(k: int, word: str) -> str:
    return f"{k} {word}" + ("" if k == 1 else ("" if word.endswith("s") else "s"))


def _t(value: str | None, ref: str | None) -> str | None:
    """An ISO time shown in the time zone of ``ref`` (the 'became aware' time), to the minute."""
    from datetime import datetime

    if not value:
        return None
    dt = datetime.fromisoformat(value)
    tz = datetime.fromisoformat(ref).tzinfo if ref else None
    if tz is not None:
        dt = dt.astimezone(tz)
    off = dt.strftime("%z")
    return dt.strftime("%d %b %Y, %H:%M") + (f" (UTC{off[:3]}:{off[3:]})" if off else "")


def _window(rep: dict) -> str:
    w, ref = rep["window"], rep["aware_at"]
    start = _t(w["start"], ref) or TODO.format("start time")
    if w.get("end_known", True):
        return f"{start} to {_t(w['end'], ref)}"
    return f"{start} until at least {_t(w['end'], ref)} (end not yet known)"


def _types(types: list[str]) -> str:
    return ", ".join(label(t) for t in types) if types else "categories not recorded"


def _contact(contact: str | None) -> str:
    return contact or TODO.format("business contact of the person who answers queries (rights.contact is not set)")


def _extent(rep: dict) -> list[str]:
    t = rep["totals"]
    lines = [f"Data Principals affected (from lineage records): **{t['affected']}**"
             + (f"; possibly affected: {t['possibly_affected']}" if t["possibly_affected"] else "")]
    for k, n in t["by_exposure"].items():
        if n:
            lines.append(f"{n} with data held as {EXPOSURE[k]}")
    if t["by_element_type"]:
        lines.append("Categories of personal data: "
                     + ", ".join(f"{label(k)} ({n})" for k, n in t["by_element_type"].items()))
    if rep["untracked_systems"] or any(not s["tracked"] for s in rep["stores"]):
        lines.append("**Incomplete:** some systems have no lineage records; their affected people are not counted "
                     "above (see Systems)")
    return lines


def _systems(rep: dict) -> list[str]:
    out = []
    for s in rep["stores"]:
        where = ", ".join(x for x in (s.get("platform"), s.get("region")) if x) or "location not recorded"
        proc = f"; processor: {s['processor']}" if s.get("processor") else ""
        out.append(f"`{s['store']}`" + (f" ({s['system']})" if s.get("system") else "") + f": {where}; "
                   f"{_n(s['artifacts'], 'record')}, {_n(s['people'], 'person') if s['people'] == 1 else str(s['people']) + ' people'}{proc}"
                   + ("" if s["tracked"] else " — **no lineage records**"))
    for u in rep["untracked_systems"]:
        out.append(f"{u['system']} ({u.get('platform') or 'platform not recorded'}): no connector, affected people "
                   "not known to the framework")
    return out


def _likely_impact(rep: dict) -> str:
    t = rep["totals"]["by_exposure"]
    parts = []
    if t.get("raw") or t.get("tokens_readable"):
        parts.append(f"{t.get('raw', 0) + t.get('tokens_readable', 0)} people's personal data may be readable by "
                     "whoever obtained it")
    if t.get("tokens"):
        parts.append(f"{t['tokens']} people's data was held only as tokens, which cannot be read without the "
                     "separately secured vault")
    if t.get("key_destroyed"):
        parts.append(f"{t['key_destroyed']} people had already been erased; their tokens cannot be read by anyone")
    return "; ".join(parts) + ". " + TODO.format("assess the likely harm (fraud, identity misuse, distress)")


def _header(rep: dict, title: str) -> list[str]:
    ref = rep["aware_at"]
    return [f"# {title}", "",
            f"Breach `{rep['breach_id']}` · assessment `{rep['assessment_id']}` · {rep['basis']}",
            f"Rule set {rep['rule_set']['id']} {rep['rule_set']['version']} · assessed by {rep['assessed_by']} "
            f"on {_t(rep['assessed_at'], ref)}", "",
            "> Draft for the DPO. Complete every `[DPO: ...]` item and have it reviewed before sending.", "",
            f"- Became aware: {_t(ref, ref)}",
            f"- Occurred: {_window(rep)}",
            f"- Nature: {rep.get('nature') or TODO.format('what happened, e.g. unauthorised access to a log store')}"]


def board_initial(rep: dict, rules: dict, contact: str | None) -> str:
    b = rules["board_initial"]
    out = _header(rep, "Intimation of personal data breach to the Data Protection Board (initial)")
    out += [f"- Due: {b['when']} ({b['basis']})", "", "## Description", "", "### Extent", ""]
    out += [f"- {x}" for x in _extent(rep)]
    out += ["", "### Systems and location", ""] + [f"- {x}" for x in _systems(rep)]
    out += ["", "## Likely impact", "", _likely_impact(rep), "", "## Contact", "", _contact(contact), ""]
    return "\n".join(out)


def board_detailed(rep: dict, rules: dict, contact: str | None) -> str:
    b = rules["board_detailed"]
    t = rep["totals"]
    out = _header(rep, "Detailed report of personal data breach to the Data Protection Board")
    out += [f"- Due by: **{_t(rep['deadlines']['board_detailed']['due_by'], rep['aware_at'])}** ({b['within_hours']} hours of becoming "
            f"aware; {b['basis']}" + ("; the Board may extend this on a written request" if b.get("extendable")
                                      else "") + ")", ""]
    sections = [
        ("Updated and detailed description", _extent(rep) + ["Systems: " + "; ".join(_systems(rep))]),
        ("Facts: events, circumstances and reasons", [TODO.format("timeline, root cause, how it was detected")]),
        ("Measures implemented or proposed to mitigate risk",
         (["Vault compromised: rotate the key-encryption key and treat all tokens as readable"]
          if rep["vault_compromised"] else []) + [TODO.format("containment, credential rotation, access review")]),
        ("Findings regarding the person who caused the breach", [TODO.format("findings, or 'under investigation'")]),
        ("Remedial measures to prevent recurrence", [TODO.format("controls added, with owners and dates")]),
        ("Intimations given to affected Data Principals",
         [f"{t['affected']} notices drafted (notices.jsonl); {t['without_contact_on_record']} affected people have no "
          "email or phone on record and need another channel; "
          f"{t['already_erased']} had been erased and cannot be contacted",
          TODO.format("how and when the notices were sent, and how many were delivered")]),
    ]
    for (title, lines) in sections:
        out += [f"## {title}", ""] + [f"- {x}" for x in lines] + [""]
    if rep["notes"]:
        out += ["## Assessment notes", ""] + [f"- {n}" for n in rep["notes"]] + [""]
    out += ["## Contact", "", _contact(contact), ""]
    return "\n".join(out)


_CONSEQUENCE = {
    "raw": "Someone may have seen this information about you.",
    "tokens_readable": "Someone may have been able to read this information about you.",
    "tokens": "The information was stored in a protected form that cannot be read without a separate key, which we "
              "believe was not exposed.",
    "key_destroyed": "Your data had already been erased; what was exposed cannot be read by anyone.",
}


def principal_notices(rep: dict, rules: dict, contact: str | None) -> list[dict]:
    """One draft per affected Data Principal, in plain language, with the Rule 7(1)(a) contents."""
    out = []
    for p in rep["affected"]:
        if p["status"] == "erased":
            continue                  # no contact details remain; reported to the Board in the detailed report
        text = "\n".join([
            "We are writing to tell you about a security incident that involved your personal data.",
            "",
            f"What happened: {rep.get('nature') or TODO.format('plain-language description')}, "
            f"{_window(rep)}.",
            f"What it involved: {_types(p['element_types'])}.",
            f"What this may mean for you: {_CONSEQUENCE[p['exposure']]}",
            f"What we have done: {TODO.format('measures taken and being taken')}",
            f"What you can do: {TODO.format('steps such as watching for suspicious messages or changing passwords')}",
            f"Questions: {_contact(contact)}",
        ])
        out.append({"principal_id": p["principal_id"], "breach_id": rep["breach_id"], "exposure": p["exposure"],
                    "element_types": p["element_types"], "contact_on_record": p["contact_on_record"],
                    "basis": rules["principals"]["basis"], "due": rules["principals"]["when"], "text": text})
    return out


def summary_markdown(rep: dict) -> str:
    d = rep["deadlines"]
    out = [f"# Breach {rep['breach_id']}: impact summary", "",
           f"Assessed by {rep['assessed_by']} on {_t(rep['assessed_at'], rep['aware_at'])} · became aware "
           f"{_t(rep['aware_at'], rep['aware_at'])} · occurred {_window(rep)}", "",
           "| Deadline | When |", "|---|---|",
           f"| Notify each affected Data Principal ({d['principals']['basis']}) | {d['principals']['when']} |",
           f"| Initial intimation to the Board ({d['board_initial']['basis']}) | {d['board_initial']['when']} |",
           f"| Detailed report to the Board ({d['board_detailed']['basis']}) | by "
           f"{_t(d['board_detailed']['due_by'], rep['aware_at'])} |",
           "", "## Extent", ""] + [f"- {x}" for x in _extent(rep)]
    out += ["", "## Systems", ""] + [f"- {x}" for x in _systems(rep)]
    if rep["notes"]:
        out += ["", "## Notes", ""] + [f"- {n}" for n in rep["notes"]]
    out += ["", "Every personal data breach is intimated: the Rules set no risk threshold. This summary lists only "
            "what the lineage graph records; it is not a substitute for the incident investigation.", ""]
    return "\n".join(out)
