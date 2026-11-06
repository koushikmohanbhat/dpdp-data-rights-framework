"""Render the insurance demo as one self-contained HTML page (no network needed to view it).

Called by demo.py --html. Input is a plain dict collected while the demo runs, so this module has no
framework dependencies and can be read on its own.
"""
from __future__ import annotations

import html
import re
from datetime import datetime, timezone

TOKEN = re.compile(r"<([A-Z][A-Z0-9_]*?)_([0-9a-f]{12})>")

ACTION_LABEL = {
    "delete": "Deleted",
    "redact": "Redacted",
    "regenerate": "Rebuilt without her",
    "retain_legal_hold": "Kept under legal hold",
    "retain_aggregate": "Kept as anonymised aggregate",
    "crypto_shred": "Made unreadable",
    "flag_retrain": "Model flagged for retraining",
    "skip": "No action",
}
ACTION_CLASS = {
    "delete": "a-del", "redact": "a-red", "regenerate": "a-regen", "retain_legal_hold": "a-hold",
    "retain_aggregate": "a-hold", "crypto_shred": "a-shred", "flag_retrain": "a-regen", "skip": "a-none",
}
EDGE_HELP = {
    "direct": "contains her data",
    "copy": "copied from",
    "embed": "embedded from",
    "transform": "derived from",
    "aggregate": "rolled up from",
    "train": "trained on",
}
PURPOSE_LABEL = {
    "policy_issuance": "Policy issuance",
    "analytics": "Analytics",
    "marketing": "Marketing",
    "model_improvement": "Agent improvement",
    "kyc_regulatory": "KYC (legal hold)",
}


def esc(s) -> str:
    return html.escape(str(s), quote=True)


def mark_tokens(text: str) -> str:
    out, cur = [], 0
    for m in TOKEN.finditer(text):
        out.append(esc(text[cur:m.start()]))
        out.append(f'<span class="tok" title="token for a {esc(m.group(1).lower())}">{esc(m.group(0))}</span>')
        cur = m.end()
    out.append(esc(text[cur:]))
    s = "".join(out)
    return s.replace("[ERASED]", '<span class="erased">[ERASED]</span>')


def mark_pii(text: str, spans: list[tuple[int, int, str]]) -> str:
    out, cur = [], 0
    for start, end, typ in sorted(spans):
        if start < cur:
            continue
        out.append(esc(text[cur:start]))
        out.append(f'<span class="pii" title="{esc(typ)}">{esc(text[start:end])}</span>')
        cur = end
    out.append(esc(text[cur:]))
    return "".join(out)


def action_pill(action: str) -> str:
    return f'<span class="pill {ACTION_CLASS.get(action, "a-none")}">{esc(ACTION_LABEL.get(action, action))}</span>'


# ---- lineage graph (inline SVG) ------------------------------------------------------------------------
def lineage_svg(nodes: list[dict], person: str) -> str:
    """nodes: artifact_id, label, depth, edge, parents, action, discovered."""
    w, h, gap, colgap, pad = 255, 38, 12, 64, 16
    cols: dict[int, list[dict]] = {}
    for n in sorted(nodes, key=lambda n: (n.get("discovered", False), n["action"] == "redact", n["label"])):
        cols.setdefault(n["depth"] + 1, []).append(n)
    cols[0] = [{"artifact_id": "_person", "label": f"{person}'s personal data", "action": "_person"}]
    ncol = max(cols) + 1
    rows = max(len(v) for v in cols.values())
    height = pad * 2 + rows * (h + gap)
    width = pad * 2 + ncol * w + (ncol - 1) * colgap
    pos: dict[str, tuple[float, float]] = {}
    for c, items in cols.items():
        col_h = len(items) * (h + gap) - gap
        y0 = (height - col_h) / 2
        for i, n in enumerate(items):
            pos[n["artifact_id"]] = (pad + c * (w + colgap), y0 + i * (h + gap))

    edges = []
    for n in nodes:
        parents = n.get("parents") or []
        srcs = parents if (n["depth"] > 0 and parents) else ["_person"]
        for p in srcs:
            if p not in pos:
                continue
            x1, y1 = pos[p][0] + w, pos[p][1] + h / 2
            x2, y2 = pos[n["artifact_id"]][0], pos[n["artifact_id"]][1] + h / 2
            mx = (x1 + x2) / 2
            edges.append(f'<path class="edge e-{esc(n["edge"])}" d="M{x1:.0f},{y1:.0f} C{mx:.0f},{y1:.0f} '
                         f'{mx:.0f},{y2:.0f} {x2:.0f},{y2:.0f}"/>')

    boxes = []
    for items in cols.values():
        for n in items:
            x, y = pos[n["artifact_id"]]
            cls = "n-person" if n["action"] == "_person" else ACTION_CLASS.get(n["action"], "a-none")
            label = n["label"] if len(n["label"]) <= 36 else n["label"][:34] + "…"
            dash = ' stroke-dasharray="5 4"' if n.get("discovered") else ""
            title = n["label"] + (f" · {ACTION_LABEL.get(n['action'], n['action'])}" if n["action"] != "_person" else "")
            boxes.append(
                f'<g class="node {cls}"><title>{esc(title)}</title>'
                f'<rect x="{x:.0f}" y="{y:.0f}" width="{w}" height="{h}" rx="6"{dash}/>'
                f'<text x="{x + 12:.0f}" y="{y + h / 2 + 4:.0f}">{esc(label)}</text></g>')

    heads = []
    for c in range(ncol):
        x = pad + c * (w + colgap)
        text = ["The person", "Holds her data directly", "Derived from those", "Derived further"][min(c, 3)]
        heads.append(f'<text class="colhead" x="{x:.0f}" y="12">{text}</text>')
    return (f'<svg viewBox="0 -8 {width:.0f} {height + 8:.0f}" width="{width:.0f}" role="img" '
            f'aria-label="Lineage graph of everything {esc(person)}\'s data turned into">'
            + "".join(heads) + "".join(edges) + "".join(boxes) + "</svg>")


# ---- page ---------------------------------------------------------------------------------------------
CSS = """
:root{
  /* Compliance report: ink on paper, one indigo accent, semantic action colours. Single column, summary first. */
  --paper:#f6f7f9; --card:#ffffff; --ink:#1b2130; --muted:#5b6475; --line:#dde1e8; --accent:#3346a8;
  --del:#b4322f; --del-bg:#fbeceb; --red:#9a6200; --red-bg:#fdf3df; --regen:#1f6aa5; --regen-bg:#e6f0f9;
  --hold:#6a3fa0; --hold-bg:#f1eafa; --ok:#25744a; --ok-bg:#e5f4ec; --tok:#3346a8; --tok-bg:#eaedfb;
  --pii:#b4322f; --pii-bg:#fbeceb;
  --display:"IBM Plex Sans",system-ui,-apple-system,"Segoe UI",sans-serif;
  --body:"IBM Plex Sans",system-ui,-apple-system,"Segoe UI",sans-serif;
  --mono:"IBM Plex Mono",ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
  color-scheme:light;
}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){
  --paper:#12151c; --card:#1a1f29; --ink:#e6e9ef; --muted:#9aa3b5; --line:#2c3341; --accent:#8c9cf2;
  --del:#f08a86; --del-bg:#3a1e1e; --red:#e9b65c; --red-bg:#3a2e17; --regen:#7cb6e8; --regen-bg:#17293a;
  --hold:#c3a2ee; --hold-bg:#2a2140; --ok:#6fd09b; --ok-bg:#16301f; --tok:#a9b5f6; --tok-bg:#232a4a;
  --pii:#f08a86; --pii-bg:#3a1e1e; color-scheme:dark;}}
:root[data-theme="dark"]{
  --paper:#12151c; --card:#1a1f29; --ink:#e6e9ef; --muted:#9aa3b5; --line:#2c3341; --accent:#8c9cf2;
  --del:#f08a86; --del-bg:#3a1e1e; --red:#e9b65c; --red-bg:#3a2e17; --regen:#7cb6e8; --regen-bg:#17293a;
  --hold:#c3a2ee; --hold-bg:#2a2140; --ok:#6fd09b; --ok-bg:#16301f; --tok:#a9b5f6; --tok-bg:#232a4a;
  --pii:#f08a86; --pii-bg:#3a1e1e; color-scheme:dark;}
*{box-sizing:border-box}
body{margin:0;background:var(--paper);color:var(--ink);font:15px/1.55 var(--body)}
main{max-width:1080px;margin:0 auto;padding:32px 20px 64px;display:grid;gap:28px}
h1,h2,h3{font-family:var(--display);text-wrap:balance;margin:0}
h1{font-size:30px;line-height:1.2;font-weight:600}
h2{font-size:21px;font-weight:600;display:flex;gap:10px;align-items:baseline}
h2 .step{font:600 13px var(--mono);color:var(--accent)}
h3{font-size:15px;font-weight:600}
p{margin:0;max-width:72ch}
.lede{color:var(--muted);font-size:16px}
section{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:22px;display:grid;gap:14px}
.why{border-left:3px solid var(--accent);padding:2px 0 2px 12px;color:var(--muted);font-size:14px;max-width:80ch}
.why b{color:var(--ink)}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}
.tile{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
.tile .n{font:600 28px var(--display);font-variant-numeric:tabular-nums}
.tile .l{color:var(--muted);font-size:13px}
.grid2{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:14px}
.box{border:1px solid var(--line);border-radius:8px;padding:12px 14px;display:grid;gap:6px;min-width:0;align-content:start}
.box .cap{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.04em}
.text{font:13px/1.6 var(--mono);overflow-wrap:anywhere}
.tok{background:var(--tok-bg);color:var(--tok);border-radius:4px;padding:0 3px}
.pii{background:var(--pii-bg);color:var(--pii);border-radius:4px;padding:0 3px;font-weight:600}
.erased{background:var(--del-bg);color:var(--del);border-radius:4px;padding:0 3px;font-weight:600}
.scroll{overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:14px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:12px;color:var(--muted);font-weight:600;text-transform:uppercase;letter-spacing:.04em}
td.num,th.num{text-align:right;font-variant-numeric:tabular-nums}
.pill{display:inline-block;font-size:12px;font-weight:600;border-radius:999px;padding:2px 9px;white-space:nowrap}
.a-del{background:var(--del-bg);color:var(--del)} .a-red{background:var(--red-bg);color:var(--red)}
.a-regen{background:var(--regen-bg);color:var(--regen)} .a-hold{background:var(--hold-bg);color:var(--hold)}
.a-shred,.a-none{background:var(--line);color:var(--muted)} .ok{background:var(--ok-bg);color:var(--ok)}
.yes{color:var(--ok);font-weight:600} .no{color:var(--muted)} .gone{color:var(--del);font-weight:600}
.chips{display:flex;flex-wrap:wrap;gap:6px}
.chip{font-size:12px;border:1px solid var(--line);border-radius:999px;padding:1px 8px;color:var(--muted)}
.blocked{background:var(--del-bg);color:var(--del);border-radius:8px;padding:12px 14px;font:13px/1.5 var(--mono)}
svg{display:block;max-width:none}
svg .colhead{font:600 11px var(--body);fill:var(--muted);text-transform:uppercase;letter-spacing:.05em}
svg .edge{fill:none;stroke:var(--line);stroke-width:1.6}
svg .e-aggregate{stroke:var(--hold);stroke-dasharray:2 3} svg .e-transform{stroke:var(--regen)}
svg .node rect{stroke-width:1.5} svg .node text{font:12.5px var(--body);fill:var(--ink)}
svg .n-person rect{fill:var(--accent);stroke:var(--accent)} svg .n-person text{fill:#fff;font-weight:600}
svg .a-del rect{fill:var(--del-bg);stroke:var(--del)} svg .a-red rect{fill:var(--red-bg);stroke:var(--red)}
svg .a-regen rect{fill:var(--regen-bg);stroke:var(--regen)} svg .a-hold rect{fill:var(--hold-bg);stroke:var(--hold)}
svg .a-none rect,svg .a-shred rect{fill:var(--card);stroke:var(--line)}
.legend{display:flex;flex-wrap:wrap;gap:8px 14px;font-size:13px;color:var(--muted);align-items:center}
code{white-space:nowrap;font:13px var(--mono);background:var(--paper);border:1px solid var(--line);border-radius:4px;padding:0 4px}
pre{font:13px/1.5 var(--mono);background:var(--paper);border:1px solid var(--line);border-radius:8px;padding:12px;overflow-x:auto;margin:0}
footer{color:var(--muted);font-size:13px;display:grid;gap:6px}
a{color:var(--accent)}
a:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
@media (max-width:600px){main{padding:20px 14px 48px} section{padding:16px} h1{font-size:24px}}
"""


def render(r: dict) -> str:
    res, person = r["result"], r["person"]
    acts = res["actions"]
    ver = res["verification"]
    ver_ok = sum(1 for v in ver if v["ok"])
    parts: list[str] = []
    add = parts.append

    add(f"""<header style="display:grid;gap:10px">
<h1>DPDP Data Rights Framework: insurance onboarding demo</h1>
<p class="lede">An AI agent onboards four insurance applicants. Their personal data spreads into application
records, a vector index, an agent cache, underwriting notes, a marketing audience, an evaluation set, logs and a
weekly report. Then one applicant withdraws a single consent, and another withdraws all consent and asks to be erased.
This report shows what the framework did at each step.</p>
<p class="lede" style="font-size:13px">All people and identifiers are fictional. Generated {esc(r['generated'])}.</p>
</header>""")

    add(f"""<div class="tiles">
<div class="tile"><div class="n">{res['artifacts_in_scope']}</div><div class="l">copies of {esc(person)}'s data found</div></div>
<div class="tile"><div class="n">{acts.get('delete', 0)}</div><div class="l">deleted</div></div>
<div class="tile"><div class="n">{acts.get('redact', 0)}</div><div class="l">redacted in other people's records</div></div>
<div class="tile"><div class="n">{acts.get('regenerate', 0)}</div><div class="l">rebuilt without her</div></div>
<div class="tile"><div class="n">{acts.get('retain_legal_hold', 0)}</div><div class="l">kept under legal hold, sealed</div></div>
<div class="tile{'' if ver_ok == len(ver) else ' a-del'}"><div class="n">{ver_ok}/{len(ver)}</div><div class="l">stores verified clean</div></div>
</div>""")

    # 1. applicants
    cards = []
    for a in r["applicants"]:
        chips = "".join(f'<span class="chip">{esc(PURPOSE_LABEL.get(p, p))}</span>' for p in a["consents"])
        cards.append(f"""<div class="box">
<h3>{esc(a['name'])} <span class="no" style="font-weight:400">· {esc(a['product'])}</span></h3>
<div class="no" style="font-size:13px">pseudonymous ID <code>{esc(a['pid'])}</code></div>
<div class="chips">{chips}</div>
<div class="cap">What they told the agent</div><div class="text">{mark_pii(a['raw'], a['spans'])}</div>
<div class="cap">What the agent, logs and stores received</div><div class="text">{mark_tokens(a['stored'])}</div>
</div>""")
    add(f"""<section><h2><span class="step">01</span>Personal data is tokenised before anything stores it</h2>
<p class="why"><b>Why it matters:</b> every model call, log line, vector and cache entry holds tokens such as
<span class="tok">&lt;EMAIL_…&gt;</span>, never the raw value. Each person has their own encryption key, so
destroying one key makes every copy of their data unreadable, including copies in logs and backups.
Detection is India-aware: Aadhaar (with checksum), PAN, UPI IDs, +91 numbers, vehicle numbers, digits in
Indian scripts, and names in Hinglish and Indian languages (Anita writes in Hinglish, Vikram in Hindi). Only what
the detectors recognise is tokenised; production adds an NER or LLM detector for names and addresses without cues.</p>
<div class="grid2">{''.join(cards)}</div>
<div class="legend"><span><span class="pii">red</span> personal data detected</span>
<span><span class="tok">blue</span> token stored in its place</span></div></section>""")

    # 2. consent matrix
    purposes = r["purposes"]
    head = "".join(f"<th>{esc(PURPOSE_LABEL.get(p, p))}</th>" for p in purposes)
    rows = []
    for a in r["applicants"]:
        cells = []
        for p in purposes:
            final = r["consent_final"].get(a["ext"], {}).get(p)
            if p not in a["consents"]:
                cells.append('<td class="no">not given</td>')
            elif final == "withdrawn":
                cells.append('<td><span class="gone">withdrawn</span></td>')
            else:
                cells.append('<td class="yes">given</td>')
        rows.append(f"<tr><td>{esc(a['name'])}</td>{''.join(cells)}</tr>")
    add(f"""<section><h2><span class="step">02</span>Consent is recorded per person, per purpose</h2>
<p class="why"><b>DPDP Act s.6:</b> consent must be specific to a purpose and as easy to withdraw as to give.
The framework checks consent on every call to <code>protect()</code>. KYC records are kept under a legal basis
other than consent (legitimate use with a legal hold), so withdrawing consent does not remove them.</p>
<div class="scroll"><table><thead><tr><th>Applicant</th>{head}</tr></thead><tbody>{''.join(rows)}</tbody></table></div>
<p class="no" style="font-size:13px">State at the end of the demo. "Withdrawn" marks the changes made in steps 03 and 05.</p></section>""")

    # 3. Anita
    an = r["anita"]
    add(f"""<section><h2><span class="step">03</span>{esc(an['name'])} withdraws marketing consent only</h2>
<p class="why"><b>DPDP Act s.6(6) and s.8(7):</b> after withdrawal, stop processing for that purpose and erase the
data held for it. Data she gave for other purposes stays, because those consents are still valid.</p>
<div class="scroll"><table><thead><tr><th>Store</th><th>Item</th><th>Before</th><th>After</th></tr></thead><tbody>
<tr><td>audiences</td><td>Her cross-sell audience entry</td><td class="num">1</td><td class="num gone">{an['audience_after']}</td></tr>
<tr><td>applications</td><td>Her insurance application</td><td class="num">1</td><td class="num yes">{an['application_after']}</td></tr>
</tbody></table></div></section>""")

    # 4. lineage
    add(f"""<section><h2><span class="step">04</span>Lineage: everything {esc(person)}'s data turned into</h2>
<p class="why"><b>The core problem:</b> consent was recorded once, against the customer, but her data spread
into {res['artifacts_in_scope']} places, some derived from others. The framework records each one with how it was
derived (copy, embedding, per-person summary, roll-up across people). Colours show what erasure did to each item.
The dashed box is a cache row written by code that bypassed the framework and never registered it: discovery found it anyway.</p>
<div class="scroll">{lineage_svg(r['graph'], person)}</div>
<div class="legend">{action_pill('delete')}{action_pill('redact')}{action_pill('regenerate')}{action_pill('retain_legal_hold')}
<span>dashed border: found by discovery, never registered</span><span>purple dotted line: roll-up across several people</span></div></section>""")

    # 5. plan
    prow = "".join(
        f"<tr><td>{esc(p['label'])}</td><td><code>{esc(p['store'])}</code></td><td>{action_pill(p['action'])}</td>"
        f"<td>{esc(p['reason'])}</td></tr>" for p in r["plan"])
    add(f"""<section><h2><span class="step">05</span>{esc(person)} withdraws all consent and asks to be erased</h2>
<p class="why"><b>DPDP Act s.12(3):</b> erase on request, unless another law requires retention. A dry run first
shows the plan: one decision per item, with the reason. Her email in Rahul's application (she is his nominee) is
redacted, not deleted, because the record is his. The weekly report covers fewer than k people, so it is rebuilt
without her rather than kept.</p>
<div class="scroll"><table><thead><tr><th>Item</th><th>Store</th><th>Decision</th><th>Reason</th></tr></thead>
<tbody>{prow}</tbody></table></div>
<h3>Further processing is refused</h3>
<p>With consent withdrawn, the agent tried to process a new message from her. The framework refused before any model saw it:</p>
<div class="blocked">{esc(r['blocked'])}</div></section>""")

    # 6. before / after
    ba = r["before_after"]
    crow = "".join(
        f"<tr><td>{esc(c['what'])}</td><td class=\"num\">{esc(c['before'])}</td><td class=\"num\">{esc(c['after'])}</td>"
        f"<td>{esc(c['note'])}</td></tr>" for c in ba["counts"])
    add(f"""<section><h2><span class="step">06</span>After the erasure</h2>
<div class="grid2">
<div class="box"><div class="cap">Rahul's application, before</div><div class="text">{mark_pii(ba['rahul_before'], ba['rahul_spans'])}</div></div>
<div class="box"><div class="cap">Rahul's application, after</div><div class="text">{mark_tokens(ba['rahul_after'])}</div></div>
<div class="box"><div class="cap">Weekly portfolio report, before</div><div class="text">{esc(ba['weekly_before'])}</div></div>
<div class="box"><div class="cap">Weekly portfolio report, after (rebuilt)</div><div class="text">{esc(ba['weekly_after'])}</div></div>
</div>
<div class="scroll"><table><thead><tr><th>What</th><th class="num">Before</th><th class="num">After</th><th>Why</th></tr></thead>
<tbody>{crow}</tbody></table></div>
<p class="no" style="font-size:13px">The demo uses an offline echo model, so the rebuilt report text is a placeholder. With a real model
(OpenAI, Claude, Bedrock or Vertex) it is rewritten from the remaining applications.</p></section>""")

    # 7. certificate
    def vrow(v: dict) -> str:
        pill = '<span class="pill ok">Clean</span>' if v["ok"] else '<span class="pill a-del">Found leftovers</span>'
        detail = esc(v.get("note") or "")
        if v.get("findings"):
            detail += " · " + esc("; ".join(map(str, v["findings"][:2])))
        return f"<tr><td><code>{esc(v['store'])}</code></td><td>{pill}</td><td>{detail}</td></tr>"

    vrows = "".join(vrow(v) for v in ver)
    exc = "".join(
        f"<li><b>{esc(e.get('store'))}</b>: {esc(e.get('reason'))}"
        f"{(' (purge after ' + esc(str(e['purge_after'])[:10]) + ')') if e.get('purge_after') else ''}</li>"
        for e in res["exceptions"])
    add(f"""<section><h2><span class="step">07</span>Verification and the erasure certificate</h2>
<p class="why"><b>Evidence:</b> after acting, every store is checked again for her tokens and for her raw values
(held in memory only during the run). The certificate records every item, decision, exception and legal basis,
and is hash-chained to the previous certificate. In production it is signed with a KMS key and stored in
write-once storage, for the DPO or the Data Protection Board.</p>
<div class="scroll"><table><thead><tr><th>Store</th><th>Result</th><th>Detail</th></tr></thead><tbody>{vrows}</tbody></table></div>
<div class="grid2">
<div class="box"><div class="cap">Certificate</div><div class="text">request {esc(res['request_id'])}<br>status {esc(res['status'])}<br>
sha256 {esc(res.get('certificate_sha256', ''))}</div></div>
<div class="box"><div class="cap">Exceptions recorded</div><ul style="margin:0;padding-left:18px;font-size:14px">{exc}</ul></div>
</div>
<p style="font-size:14px"><b>Rule 8(3) of the DPDP Rules 2025</b> asks for personal data, traffic data and processing logs to be kept
for at least one year. The framework keeps her identifiers in a sealed escrow that applications cannot use. Only audited,
two-person break-glass access can read it, and a daily job destroys it when the year ends. Full records, log retention
and traffic data need deployment settings (see docs/dpdp-mapping.md).</p></section>""")

    add("""<footer>
<p>Generated by <code>python examples/insurance_onboarding/demo.py --html</code>. Run it with <code>--leak</code> to see
verification catch a raw phone number written by a legacy job.</p>
<p>Step-by-step explanation: docs/demo-walkthrough.md. DPDP mapping: docs/dpdp-mapping.md.
Not legal advice; validate with privacy counsel.</p>
</footer>""")

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>DPDP Erasure Demo Report</title>
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=IBM+Plex+Sans:wght@400;600&display=swap" rel="stylesheet">
<style>{CSS}</style></head>
<body><main>{''.join(parts)}</main></body></html>
"""


def now() -> str:
    return datetime.now(timezone.utc).strftime("%d %b %Y, %H:%M UTC")
