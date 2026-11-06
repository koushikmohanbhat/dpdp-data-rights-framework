"""Deployment inventory and coverage report.

An inventory (YAML) lists every system in an engagement that may hold personal data: what it is, where it
runs, who owns it, which purposes and data elements it holds, which processor runs it, and how a rights
request reaches it (a framework connector, or a documented manual procedure).

``coverage_report`` compares the inventory with the framework config and the connectors' declared
capabilities, and says per system what is automated, what has limits, what is manual, and what is a gap.
It reads files only: no database, cloud or network access, so it can run in a discovery workshop.
"""
from __future__ import annotations

import html
import json
from datetime import date, timedelta
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field

from ..core.config import FrameworkConfig
from .capabilities import load_matrix

Category = Literal["database", "vector_store", "cache", "agent_memory", "logs", "traces", "object_store",
                   "dataset", "warehouse", "model_provider", "saas", "identity", "backup", "other"]
LOG_CATEGORIES = {"logs", "traces"}
INDIA_REGIONS = ("ap-south-1", "ap-south-2", "asia-south1", "asia-south2", "centralindia", "southindia",
                 "westindia", "india", "in")
RETEST_DAYS = 180


class Engagement(BaseModel):
    client: str
    system: str = ""                 # the agent or application in scope
    prepared_by: str = ""
    dpo: str = ""
    prepared_on: date | None = None


class InventorySystem(BaseModel):
    name: str
    description: str = ""
    category: Category = "other"
    platform: str = ""               # e.g. "Aurora PostgreSQL", "AgentCore Memory", "Zendesk"
    holds_personal_data: bool = True
    data_elements: list[str] = Field(default_factory=list)
    purposes: list[str] = Field(default_factory=list)
    region: str = ""
    owner: str = ""
    processor: str | None = None     # third party that runs it on the client's behalf
    processor_contract: str | None = None   # reference to the clause requiring erasure on instruction
    connector: str | None = None     # connector name in the framework config
    manual_procedure: str | None = None     # runbook reference when there is no connector
    retention_days: int | None = None
    tested_on: date | None = None    # last successful end-to-end test of the actions on this system
    test_evidence: str | None = None
    notes: str = ""


class Inventory(BaseModel):
    engagement: Engagement
    systems: list[InventorySystem]

    @classmethod
    def load(cls, path: str) -> Inventory:
        with open(path, encoding="utf-8") as f:
            return cls.model_validate(yaml.safe_load(f))


STATUS_ORDER = ["gap", "manual", "automated_with_limits", "automated", "out_of_scope"]
STATUS_LABEL = {"automated": "Automated", "automated_with_limits": "Automated, with limits",
                "manual": "Manual procedure", "gap": "Gap", "out_of_scope": "No personal data"}


def coverage_report(inv: Inventory, cfg: FrameworkConfig, today: date | None = None) -> dict[str, Any]:
    today = today or date.today()
    matrix = load_matrix()
    conns = {c.name: c.type for c in cfg.connectors}
    purposes = {p.id for p in cfg.purposes}
    rows, findings = [], []

    def finding(level: str, system: str | None, msg: str) -> None:
        findings.append({"level": level, "system": system, "message": msg})

    for s in inv.systems:
        row: dict[str, Any] = {"system": s.name, "category": s.category, "platform": s.platform,
                               "owner": s.owner, "region": s.region, "connector": s.connector,
                               "connector_type": None, "actions": [], "discover": None, "verify": None,
                               "limits": [], "tested": False, "tested_on": s.tested_on and s.tested_on.isoformat(),
                               "manual_procedure": s.manual_procedure, "processor": s.processor}
        if not s.holds_personal_data:
            row["status"] = "out_of_scope"
            rows.append(row)
            continue
        if s.connector:
            ctype = conns.get(s.connector)
            if ctype is None:
                row["status"] = "gap"
                finding("error", s.name, f"connector '{s.connector}' is not in the framework config")
            else:
                cap = matrix.get(ctype, {})
                row.update(connector_type=ctype, actions=cap.get("actions", []), discover=cap.get("discover"),
                           verify=cap.get("verify"), limits=cap.get("limits", []))
                row["status"] = "automated_with_limits" if (row["limits"] or cap.get("verify") == "none"
                                                            or cap.get("discover") == "lineage") else "automated"
                if cap.get("discover") == "lineage":
                    finding("info", s.name, f"{ctype} acts only on items registered with track_artifact; "
                                            "make sure every write to this system is tracked")
                if cap.get("verify") == "none":
                    finding("warning", s.name, f"{ctype} cannot verify results; record a manual check")
        elif s.manual_procedure:
            row["status"] = "manual"
        else:
            row["status"] = "gap"
            finding("error", s.name, "holds personal data but has no connector and no manual procedure")

        for p in s.purposes:
            if p not in purposes:
                finding("error", s.name, f"purpose '{p}' is not defined in the framework config")
        if s.category in LOG_CATEGORIES and s.retention_days is not None and s.retention_days < 365:
            finding("warning", s.name, f"retention {s.retention_days} days is under one year "
                                       "(DPDP Rules r.8(3) asks for processing logs to be kept at least a year)")
        if s.region and not s.region.lower().startswith(INDIA_REGIONS):
            finding("info", s.name, f"region '{s.region}' is outside India: confirm cross-border transfer "
                                    "is permitted (Act s.16) and any sectoral localisation rules")
        if s.processor and not s.processor_contract:
            finding("warning", s.name, f"processor '{s.processor}' has no contract reference: the contract "
                                       "should require erasure on instruction (Act s.8(2), s.8(7))")
        if row["status"] in ("automated", "automated_with_limits", "manual"):
            if s.tested_on is None:
                finding("warning", s.name, "actions on this system have not been tested end to end")
            elif (today - s.tested_on) > timedelta(days=RETEST_DAYS):
                finding("warning", s.name, f"last tested {s.tested_on.isoformat()}: retest (older than "
                                           f"{RETEST_DAYS} days)")
                row["tested"] = False
            else:
                row["tested"] = True
        rows.append(row)

    listed = {s.connector for s in inv.systems if s.connector}
    for name, ctype in conns.items():
        if name not in listed:
            finding("warning", None, f"connector '{name}' ({ctype}) is configured but no system in the inventory "
                                     "uses it: add the system, or remove the connector")

    in_scope = [r for r in rows if r["status"] != "out_of_scope"]
    auto = [r for r in in_scope if r["status"] in ("automated", "automated_with_limits")]
    summary = {
        "systems": len(rows),
        "in_scope": len(in_scope),
        "automated": len(auto),
        "manual": sum(r["status"] == "manual" for r in in_scope),
        "gaps": sum(r["status"] == "gap" for r in in_scope),
        "tested": sum(r["tested"] for r in in_scope),
        "automated_pct": round(100 * len(auto) / len(in_scope)) if in_scope else 0,
        "tested_pct": round(100 * sum(r["tested"] for r in in_scope) / len(in_scope)) if in_scope else 0,
        "errors": sum(f["level"] == "error" for f in findings),
        "warnings": sum(f["level"] == "warning" for f in findings),
    }
    rows.sort(key=lambda r: (STATUS_ORDER.index(r["status"]), r["system"]))
    return {"engagement": inv.engagement.model_dump(mode="json"), "generated": today.isoformat(),
            "summary": summary, "systems": rows, "findings": findings}


# ---- rendering ------------------------------------------------------------------------------------------
def _n(count: int, word: str) -> str:
    return f"{count} {word}" + ("" if count == 1 else "s")


def to_markdown(rep: dict[str, Any]) -> str:
    e, s = rep["engagement"], rep["summary"]
    out = [f"# Coverage report: {e['client']}" + (f", {e['system']}" if e.get("system") else ""), "",
           f"Generated {rep['generated']}" + (f" · prepared by {e['prepared_by']}" if e.get("prepared_by") else ""), "",
           f"**{_n(s['in_scope'], 'system')} with personal data.** {s['automated']} automated ({s['automated_pct']}%), "
           f"{s['manual']} manual, {_n(s['gaps'], 'gap')}. Actions tested end to end on {s['tested']} "
           f"({s['tested_pct']}%). {_n(s['errors'], 'error')}, {_n(s['warnings'], 'warning')}.", "",
           "| System | Category | Status | Connector | Actions | Tested | Limits |", "|---|---|---|---|---|---|---|"]
    for r in rep["systems"]:
        out.append(f"| {r['system']} | {r['category']} | {STATUS_LABEL[r['status']]} | "
                   f"{('`' + r['connector'] + '`') if r['connector'] else (r['manual_procedure'] or '-')} | "
                   f"{', '.join(r['actions']) or '-'} | "
                   f"{r['tested_on'] or '-'} | {'; '.join(r['limits']) or '-'} |")
    if rep["findings"]:
        out += ["", "## Findings", "", "| Level | System | Finding |", "|---|---|---|"]
        for f in sorted(rep["findings"], key=lambda f: ["error", "warning", "info"].index(f["level"])):
            out.append(f"| {f['level']} | {f['system'] or '-'} | {f['message']} |")
    return "\n".join(out) + "\n"


def to_json(rep: dict[str, Any]) -> str:
    return json.dumps(rep, indent=2, default=str)


_CSS = """
:root{--paper:#f6f7f9;--card:#fff;--ink:#1b2130;--muted:#5b6475;--line:#dde1e8;--accent:#3346a8;
--ok:#25744a;--ok-bg:#e5f4ec;--warn:#9a6200;--warn-bg:#fdf3df;--bad:#b4322f;--bad-bg:#fbeceb;
--body:"IBM Plex Sans",system-ui,-apple-system,"Segoe UI",sans-serif;color-scheme:light}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--paper:#12151c;--card:#1a1f29;--ink:#e6e9ef;
--muted:#9aa3b5;--line:#2c3341;--accent:#8c9cf2;--ok:#6fd09b;--ok-bg:#16301f;--warn:#e9b65c;--warn-bg:#3a2e17;
--bad:#f08a86;--bad-bg:#3a1e1e;color-scheme:dark}}
:root[data-theme="dark"]{--paper:#12151c;--card:#1a1f29;--ink:#e6e9ef;--muted:#9aa3b5;--line:#2c3341;--accent:#8c9cf2;
--ok:#6fd09b;--ok-bg:#16301f;--warn:#e9b65c;--warn-bg:#3a2e17;--bad:#f08a86;--bad-bg:#3a1e1e;color-scheme:dark}
body{margin:0;background:var(--paper);color:var(--ink);font:15px/1.5 var(--body)}
main{max-width:1100px;margin:0 auto;padding:28px 18px 56px;display:grid;gap:22px}
h1{margin:0;font-size:26px;text-wrap:balance} p{margin:0;max-width:75ch} .muted{color:var(--muted)}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px}
.tile{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
.tile b{display:block;font-size:26px;font-variant-numeric:tabular-nums}.tile span{color:var(--muted);font-size:13px}
section{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:18px;overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:14px}th,td{text-align:left;padding:7px 9px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.04em}
.pill{display:inline-block;border-radius:999px;padding:1px 9px;font-size:12px;font-weight:600;white-space:nowrap}
.automated,.info{background:var(--ok-bg);color:var(--ok)}.automated_with_limits,.manual,.warning{background:var(--warn-bg);color:var(--warn)}
.gap,.error{background:var(--bad-bg);color:var(--bad)}.out_of_scope{background:var(--line);color:var(--muted)}
code{font-size:13px}td:nth-child(6){white-space:nowrap}
"""


def to_html(rep: dict[str, Any]) -> str:
    esc = lambda v: html.escape(str(v))  # noqa: E731
    e, s = rep["engagement"], rep["summary"]
    title = f"Coverage report: {e['client']}"
    tiles = "".join(f'<div class="tile"><b>{v}</b><span>{esc(k)}</span></div>' for k, v in [
        ("systems hold personal data", s["in_scope"]), ("automated", f"{s['automated_pct']}%"),
        ("tested end to end", f"{s['tested_pct']}%"), ("manual", s["manual"]), ("gaps", s["gaps"]),
        ("errors / warnings", f"{s['errors']} / {s['warnings']}")])
    rows = "".join(
        f"<tr><td>{esc(r['system'])}<div class='muted'>{esc(r['platform'])}</div></td><td>{esc(r['category'])}</td>"
        f"<td><span class='pill {r['status']}'>{esc(STATUS_LABEL[r['status']])}</span></td>"
        f"<td>{('<code>' + esc(r['connector']) + '</code>') if r['connector'] else esc(r['manual_procedure'] or '-')}</td>"
        f"<td>{esc(', '.join(r['actions']) or '-')}</td><td>{esc(r['tested_on'] or '-')}</td>"
        f"<td>{'<br>'.join(esc(x) for x in r['limits']) or '-'}</td></tr>" for r in rep["systems"])
    fnd = "".join(
        f"<tr><td><span class='pill {f['level']}'>{esc(f['level'])}</span></td><td>{esc(f['system'] or '-')}</td>"
        f"<td>{esc(f['message'])}</td></tr>"
        for f in sorted(rep["findings"], key=lambda f: ["error", "warning", "info"].index(f["level"])))
    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>{esc(title)}</title>
<style>{_CSS}</style></head><body><main>
<header><h1>{esc(title)}{(', ' + esc(e['system'])) if e.get('system') else ''}</h1>
<p class="muted">Generated {esc(rep['generated'])}{(' · prepared by ' + esc(e['prepared_by'])) if e.get('prepared_by') else ''}.
Which systems a rights request reaches automatically, which need a manual procedure, and which are gaps.</p></header>
<div class="tiles">{tiles}</div>
<section><table><thead><tr><th>System</th><th>Category</th><th>Status</th><th>Connector</th><th>Actions</th>
<th>Tested</th><th>Limits</th></tr></thead><tbody>{rows}</tbody></table></section>
{('<section><table><thead><tr><th>Level</th><th>System</th><th>Finding</th></tr></thead><tbody>' + fnd + '</tbody></table></section>') if fnd else ''}
</main></body></html>
"""
