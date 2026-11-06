"""The rights notice to publish on the website or app (Rules r.14(1)): how to make each request, the
identifiers needed, response periods (from the effective rule set), the grievance period and escalation.
Generated from configuration, so what is published matches what the system enforces."""
from __future__ import annotations

import html

TITLES = {"access": "Get a summary of your data", "correction": "Correct, complete or update your data",
          "erasure": "Erase your data", "withdrawal": "Withdraw consent", "nomination": "Nominate someone",
          "nominee_invocation": "Act as a nominee", "grievance": "Raise a grievance"}


def published_means(source) -> dict:
    """``source``: a DataRightsFramework or a FrameworkConfig (no stores, keys or cloud access needed)."""
    from .rules import resolve

    config = getattr(source, "config", source)
    cfg = config.rights
    rs, _ = resolve(cfg.rule_set, None, cfg.overrides, cfg.rule_sets_dir)
    return {
        "schema": "dpdp-rights/rights-notice/v1",
        "rules": rs.ref() | {"commencement": str(rs.commencement) if rs.commencement else None,
                             "reviewed": rs.data.get("reviewed")},
        "channels": [c.model_dump() for c in cfg.channels],
        "identifiers": list(cfg.identifiers),
        "contact": cfg.contact,
        "requests": [{"type": k, "title": TITLES.get(k, k), "summary": v.get("summary"), "basis": v.get("basis"),
                      "respond_within_days": v.get("respond_within_days"),
                      "who": [w.replace("principal", "you").replace("nominee", "your nominee") for w in v.get("requesters", [])]}
                     for k, v in rs.data["requests"].items()],
        "grievance_period_days": rs.due_days("grievance"),
        "board_escalation": rs.data.get("board_escalation"),
        "gaps": [g for g, bad in (("rights.channels is empty: say where people make requests", not cfg.channels),
                                  ("rights.identifiers is empty: say what identifies a person", not cfg.identifiers),
                                  ("rights.contact is empty: give the DPO or grievance contact", not cfg.contact)) if bad],
    }


def notice_markdown(n: dict) -> str:
    lines = ["# Your data rights and how to use them", ""]
    if n["channels"]:
        lines += ["## Where to make a request", ""] + [f"- **{c['name']}**: {c['how']}" for c in n["channels"]] + [""]
    if n["identifiers"]:
        lines += ["## What we need to identify you", ""] + [f"- {i}" for i in n["identifiers"]] + [""]
    lines += ["## What you can ask for", "", "| Request | What it means | We respond within | Who can ask |", "|---|---|---|---|"]
    for r in n["requests"]:
        lines.append(f"| {r['title']} | {r['summary']} | {r['respond_within_days']} days | {', '.join(r['who'])} |")
    lines += ["", "## Grievances", "", f"We respond to grievances within {n['grievance_period_days']} days."]
    if n["board_escalation"]:
        lines += ["", n["board_escalation"]]
    if n["contact"]:
        lines += ["", f"Contact: {n['contact']}"]
    lines += ["", f"<!-- generated from {n['rules']['rule_set']} {n['rules']['rule_version']} "
              f"sha256 {n['rules']['rule_sha256'][:16]} -->", ""]
    return "\n".join(lines)


def notice_html(n: dict) -> str:
    e = html.escape
    rows = "".join(f"<tr><td>{e(r['title'])}</td><td>{e(r['summary'] or '')}</td><td>{r['respond_within_days']} days</td>"
                   f"<td>{e(', '.join(r['who']))}</td></tr>" for r in n["requests"])
    ch = "".join(f"<li><b>{e(c['name'])}</b>: {e(c['how'])}</li>" for c in n["channels"])
    ids = "".join(f"<li>{e(i)}</li>" for i in n["identifiers"])
    return ("<section class='dpdp-rights-notice'><h2>Your data rights and how to use them</h2>"
            + (f"<h3>Where to make a request</h3><ul>{ch}</ul>" if ch else "")
            + (f"<h3>What we need to identify you</h3><ul>{ids}</ul>" if ids else "")
            + "<h3>What you can ask for</h3><table><thead><tr><th>Request</th><th>What it means</th>"
              f"<th>We respond within</th><th>Who can ask</th></tr></thead><tbody>{rows}</tbody></table>"
            + f"<h3>Grievances</h3><p>We respond to grievances within {n['grievance_period_days']} days.</p>"
            + (f"<p>{e(n['board_escalation'])}</p>" if n["board_escalation"] else "")
            + (f"<p>Contact: {e(n['contact'])}</p>" if n["contact"] else "")
            + f"<!-- generated from {e(n['rules']['rule_set'])} {e(n['rules']['rule_version'])} -->"
            + "</section>")
