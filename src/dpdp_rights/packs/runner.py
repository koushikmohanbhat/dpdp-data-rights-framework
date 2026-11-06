"""Offline scenario tests for a domain pack, or for a client's own config.

A scenario creates people (consents, identifiers), records in named stores (each becomes a generated
offline connector), derived artifacts, then plays steps (withdraw, erase, protect, access, correct) and
checks expectations. The purposes, legal holds, policy rules, PII patterns and rights settings come from
the pack, or from ``--config`` so a partner can test a client's configuration before deploying anything.

Scenario file format: docs/domain-packs.md.
"""
from __future__ import annotations

import json
import sqlite3
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..core.config import FrameworkConfig

SQL_KINDS = {"record", "summary", "embedding", "cache_entry", "memory_record", "memory_event", "kb_document",
             "prompt", "completion"}
FILE_KINDS = {"log", "trace"}
JSONL_KINDS = {"eval_row", "finetune_row"}
TAKEN_FROM_CONFIG = ("purposes", "policy", "pii", "rights", "evidence", "enforce_consent")


@dataclass
class StepResult:
    scenario: str
    step: str
    ok: bool
    failures: list[str] = field(default_factory=list)
    detail: dict[str, Any] = field(default_factory=dict)


def _stores(scn: dict) -> dict[str, str]:
    stores: dict[str, str] = {}
    for p in scn.get("people", []):
        for r in p.get("records", []):
            stores.setdefault(r["store"], r.get("kind", "record"))
    for r in scn.get("derived", []):
        stores.setdefault(r["store"], r.get("kind", "summary"))
    return stores


def _config(fragment: dict, stores: dict[str, str], tmp: Path) -> FrameworkConfig:
    conns = []
    for name, kind in stores.items():
        if kind in FILE_KINDS:
            conns.append({"name": name, "type": "log_file", "options": {"path": str(tmp / f"{name}.log")}})
        elif kind in JSONL_KINDS:
            conns.append({"name": name, "type": "jsonl_dataset",
                          "options": {"path": str(tmp / f"{name}.jsonl"), "kind": kind}})
        else:
            conns.append({"name": name, "type": "sql_table",
                          "options": {"url": f"sqlite:///{tmp}/app.db", "table": f"t_{name}", "content_column": "body",
                                      "principal_column": "principal_id", "kind": kind}})
    base = {k: v for k, v in fragment.items() if k in TAKEN_FROM_CONFIG}
    pii = dict(base.get("pii") or {})
    pii["detectors"] = ["regex"]          # offline; cloud / NER detectors are not exercised here
    pii["allow_regex_only"] = True
    base["pii"] = pii
    return FrameworkConfig.from_dict(base | {
        "environment": "dev", "provider": {"type": "echo"},
        "vault": {"local_master_key_path": str(tmp / "m.key")},
        "lineage": {"url": f"sqlite:///{tmp}/lineage.db"},
        "certificates": {"signer": "local", "local_key_path": str(tmp / "sign.key")},
        "connectors": conns, "notifications": [], "queue": {},
    })


class _World:
    def __init__(self, fragment: dict, scn: dict, tmp: Path):
        from ..framework import DataRightsFramework

        self.stores = _stores(scn)
        self.db = sqlite3.connect(tmp / "app.db")
        for name, kind in self.stores.items():
            if kind not in FILE_KINDS | JSONL_KINDS:
                self.db.execute(f'CREATE TABLE "t_{name}" (id TEXT PRIMARY KEY, principal_id TEXT, body TEXT)')
        self.db.commit()
        self.tmp = tmp
        self.f = DataRightsFramework(_config(fragment, self.stores, tmp))
        self.pids: dict[str, str] = {}
        self.arts: dict[str, Any] = {}      # record id -> Artifact
        self.texts: dict[str, str] = {}

    def setup(self, scn: dict) -> None:
        f = self.f
        for p in scn.get("people", []):
            pid = f.principal(p["id"])
            self.pids[p["id"]] = pid
            for t, v in (p.get("identifiers") or {}).items():
                f.register_identifier(pid, t, v)
            for c in p.get("consents", []):
                f.grant_consent(pid, c)
        for p in scn.get("people", []):
            for r in p.get("records", []):
                self._write(r, p["id"])
        for r in scn.get("derived", []):
            self._write(r, None)

    def _write(self, r: dict, owner: str | None) -> None:
        f, kind = self.f, r.get("kind", self.stores[r["store"]])
        parents = [self.arts[x].artifact_id for x in r.get("from", [])]
        edge = r.get("edge")
        if owner:
            with f.context(self.pids[owner], purpose=r["purpose"]):
                safe = f.protect(r["text"])
                text, eids = safe.text, safe.element_ids
                self._store(r, kind, self.pids[owner], text)
                a = f.track_artifact(kind, r["store"], {"id": r["id"]}, content=text, element_ids=eids,
                                     parents=parents or None, edge_type=edge or "transform", purpose=r["purpose"])
        else:   # derived across people (reports, aggregates): content is built from parents' tokens
            text = r.get("text") or " ".join(self.texts[x] for x in r.get("from", []))
            self._store(r, kind, None, text)
            a = f.track_artifact(kind, r["store"], {"id": r["id"]}, content=text, parents=parents or None,
                                 edge_type=edge or "aggregate", purpose=r.get("purpose"))
        self.arts[r["id"]], self.texts[r["id"]] = a, text

    def _store(self, r, kind, pid, text):
        if kind in FILE_KINDS:
            with open(self.tmp / f"{r['store']}.log", "a", encoding="utf-8") as fh:
                fh.write(text + "\n")
        elif kind in JSONL_KINDS:
            with open(self.tmp / f"{r['store']}.jsonl", "a", encoding="utf-8") as fh:
                fh.write(json.dumps({"id": r["id"], "input": text}) + "\n")
        else:
            self.db.execute(f'INSERT INTO "t_{r["store"]}" VALUES (?,?,?)', (r["id"], pid, text))
            self.db.commit()

    def present(self, rid: str) -> bool:
        store = self.arts[rid].store
        kind = self.stores[store]
        if kind in JSONL_KINDS:
            p = self.tmp / f"{store}.jsonl"
            return p.exists() and any(json.loads(line).get("id") == rid for line in p.read_text().splitlines() if line)
        if kind in FILE_KINDS:
            return True     # immutable: crypto-shredded, never removed
        return self.db.execute(f'SELECT count(*) FROM "t_{store}" WHERE id=?', (rid,)).fetchone()[0] == 1

    def reveal(self, rid: str) -> str:
        row = self.db.execute(f'SELECT body FROM "t_{self.arts[rid].store}" WHERE id=?', (rid,)).fetchone()
        return self.f.vault.reveal(row[0]) if row else ""


def _check_erasure(w: _World, out: dict, exp: dict, fails: list[str]) -> None:
    if "status" in exp and out.get("status") != exp["status"]:
        fails.append(f"status {out.get('status')} != {exp['status']}")
    plan = {p["artifact_id"]: p["action"] for p in out.get("plan", [])}
    for rid, action in (exp.get("actions") or {}).items():
        got = plan.get(w.arts[rid].artifact_id, "untouched")
        if got != action:
            fails.append(f"{rid}: action {got} != {action}")
    for rid in exp.get("untouched", []):
        if w.arts[rid].artifact_id in plan:
            fails.append(f"{rid}: expected untouched, got {plan[w.arts[rid].artifact_id]}")
    for rid in exp.get("removed", []):
        if w.present(rid):
            fails.append(f"{rid}: still present")
    for rid in exp.get("kept", []):
        if not w.present(rid):
            fails.append(f"{rid}: removed but expected kept")
    for rid, needle in (exp.get("reads") or {}).items():
        if needle not in w.reveal(rid):
            fails.append(f"{rid}: reads {w.reveal(rid)[:80]!r}, expected to contain {needle!r}")


def run_scenario(fragment: dict, scn: dict) -> list[StepResult]:
    from ..consent.ledger import ConsentDenied

    results = []
    with tempfile.TemporaryDirectory() as d:
        w = _World(fragment, scn, Path(d))
        try:
            w.setup(scn)
        except Exception as e:  # noqa: BLE001
            return [StepResult(scn["id"], "setup", False, [f"{type(e).__name__}: {e}"])]
        f = w.f
        for i, step in enumerate(scn.get("steps", []), 1):
            (op, args), = ((k, v) for k, v in step.items() if k != "expect")
            exp, fails, detail = step.get("expect") or {}, [], {}
            name = f"{i}. {op} {args.get('person', '')} {args.get('purpose', '')}".strip()
            try:
                pid = w.pids.get(args.get("person", ""))
                if op == "withdraw":
                    out = f.withdraw_consent(pid, args["purpose"])["erasure"]
                    _check_erasure(w, out, exp, fails)
                elif op == "erase":
                    out = f.erase(pid, scope=args.get("scope", "full"))
                    _check_erasure(w, out, exp, fails)
                    detail["exceptions"] = [e.get("reason") for e in out.get("exceptions", [])]
                elif op == "protect":
                    try:
                        with f.context(pid, purpose=args["purpose"]):
                            f.protect(args.get("text", "hello"))
                        denied = False
                    except ConsentDenied:
                        denied = True
                    if "consent_denied" in exp and denied != exp["consent_denied"]:
                        fails.append(f"consent_denied {denied} != {exp['consent_denied']}")
                elif op == "access":
                    c = f.rights.submit("access", pid, requested_by="scenario")
                    if c["status"] == "in_review":
                        f.rights.decide(c["case_id"], "scenario-reviewer", "approve")
                    rep = f.rights.access_report(c["case_id"])
                    types = {d["type"] for d in rep["data"]}
                    recips = {r["name"] for r in rep["recipients"]}
                    for t in exp.get("types", []):
                        if t not in types:
                            fails.append(f"access report lacks {t} (has {sorted(types)})")
                    for r in exp.get("recipients", []):
                        if r not in recips:
                            fails.append(f"access report lacks recipient {r!r} (has {sorted(recips)})")
                    for r in exp.get("not_recipients", []):
                        if r in recips:
                            fails.append(f"access report discloses {r!r}")
                    if "due_days" in exp:
                        due = f.rights.rules().due_days("access")
                        if due != exp["due_days"]:
                            fails.append(f"access due in {due} days, expected {exp['due_days']}")
                elif op == "correct":
                    c = f.rights.submit("correction", pid, requested_by="scenario", element_type=args["element_type"],
                                        new_value=args["new_value"])
                    if c["status"] == "in_review":
                        f.rights.decide(c["case_id"], "scenario-reviewer", "approve")
                    for rid, needle in (exp.get("reads") or {}).items():
                        if needle not in w.reveal(rid):
                            fails.append(f"{rid}: reads {w.reveal(rid)[:80]!r}, expected {needle!r}")
                elif op == "grievance":
                    c = f.rights.submit("grievance", pid, requested_by="scenario", category=args.get("category", "other"),
                                        description=args.get("text", "complaint"))
                    if "due_days" in exp and f.rights.rules().due_days("grievance") != exp["due_days"]:
                        fails.append(f"grievance due in {f.rights.rules().due_days('grievance')} days, expected {exp['due_days']}")
                    detail["case"] = c["case_id"]
                else:
                    fails.append(f"unknown step '{op}'")
            except Exception as e:  # noqa: BLE001
                fails.append(f"{type(e).__name__}: {e}")
            results.append(StepResult(scn["id"], name, not fails, fails, detail))
    return results


def run_detection(fragment: dict, cases: list[dict]) -> list[StepResult]:
    from ..core.config import PIIConfig
    from ..pii.detectors import build_detector

    pii = PIIConfig(**{**(fragment.get("pii") or {}), "detectors": ["regex"]})
    det = build_detector(pii)
    out = []
    for i, c in enumerate(cases, 1):
        found = {(e.type, e.text) for e in det.detect(c["text"])}
        types = {t for t, _ in found}
        fails = [f"missed {t}" for t in c.get("types", []) if t not in types]
        fails += [f"wrongly found {t}" for t in c.get("absent", []) if t in types]
        out.append(StepResult("detection", f"{i}. {c['text'][:50]}", not fails, fails, {"found": sorted(found)}))
    return out


def run(fragment: dict, scenarios: dict) -> list[StepResult]:
    res: list[StepResult] = []
    for scn in scenarios.get("scenarios", []):
        res.extend(run_scenario(fragment, scn))
    res.extend(run_detection(fragment, scenarios.get("detection", [])))
    return res
