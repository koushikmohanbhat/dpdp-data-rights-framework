"""Breach impact assessment: who is affected, by what, and what must be intimated by when (docs/breach.md)."""
from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

from ..core.models import ArtifactStatus, PrincipalStatus, new_id, utcnow
from ..evidence.case import aware, iso

# How exposed a person's data is in a breached artifact, worst first. Every level is still a personal data
# breach (Rules r.7 has no threshold); the level shapes the "likely consequences" text, not whether to intimate.
EXPOSURE = {
    "raw": "raw values (stored before tokenisation)",
    "tokens_readable": "tokens, readable because the vault was also compromised",
    "tokens": "tokens only; unreadable without the vault",
    "key_destroyed": "tokens whose key was already destroyed (the person had been erased)",
}
ORDER = list(EXPOSURE)
CONTACT_TYPES = ("EMAIL", "PHONE_IN")
INTERNAL_TYPES = ("PRINCIPAL_REF",)
DERIVED_KINDS = ("summary", "aggregate", "model")


class BreachError(ValueError):
    """The assessment request is invalid (unknown breach, bad window, nothing named)."""


def _when(v, name: str) -> datetime | None:
    if v is None or v == "":
        return None
    if isinstance(v, str):
        try:
            v = datetime.fromisoformat(v.replace("Z", "+00:00"))
        except ValueError as e:
            raise BreachError(f"{name}: not an ISO 8601 time: {v!r}") from e
    return aware(v)


def _canon(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, default=str, separators=(",", ":"), ensure_ascii=False).encode()


class BreachDesk:
    def __init__(self, dpdp):
        self.f = dpdp

    # ---- assess ---------------------------------------------------------------------------------------------
    def assess(self, *, stores: list[str] | None = None, systems: list[str] | None = None, end=None, start=None,
               aware_at=None, vault_compromised: bool = False, assessed_by: str, breach_id: str | None = None,
               nature: str | None = None) -> dict:
        """Assess a breach of ``stores`` (connector names) and/or inventory ``systems`` between ``start`` and
        ``end``. Pass ``breach_id`` to re-assess a known breach as facts change; each assessment is kept."""
        if not assessed_by:
            raise BreachError("assessed_by is required (who made this assessment)")
        stores, systems = list(dict.fromkeys(stores or [])), list(dict.fromkeys(systems or []))
        if not stores and not systems and not vault_compromised:
            raise BreachError("name at least one store or inventory system, or set vault_compromised")
        now = utcnow()
        end_t, start_t = _when(end, "end") or now, _when(start, "start")
        aware_t = _when(aware_at, "aware_at") or now
        if start_t and start_t > end_t:
            raise BreachError("start is after end")
        if end_t > now + timedelta(minutes=5):
            raise BreachError("end is in the future")
        if breach_id and not self.f.store.breach_assessments(breach_id):
            raise BreachError(f"unknown breach {breach_id}")

        rs = self.f.rights.rules(aware_t)
        rules = rs.breach()
        if not rules:
            raise BreachError(f"rule set {rs.id} {rs.version} has no breach section")
        notes: list[str] = []
        inv_rows = self._inventory(systems, stores, notes)
        for s in inv_rows:                                    # inventory systems map to their connector
            if s.get("connector") and s["connector"] not in stores:
                stores.append(s["connector"])
        configured = set(self.f.connectors)
        for st in stores:
            if st not in configured:
                notes.append(f"store '{st}' is not a configured connector: only artifacts already recorded under "
                             "that name can be found")

        arts = self.f.store.artifacts_in_stores(stores, created_before=end_t) if stores else []
        links = self.f.store.elements_in_artifacts([a.artifact_id for a in arts])
        by_art: dict[str, list[tuple[str, str, bool]]] = defaultdict(list)
        for aid, pid, et, third in links:
            by_art[aid].append((pid, et, third))

        status_of: dict[str, str] = {}

        def pstatus(pid):
            if pid not in status_of:
                p = self.f.store.get_principal(pid)
                status_of[pid] = (p.status.value if hasattr(p.status, "value") else str(p.status)) if p else "unknown"
            return status_of[pid]

        people: dict[str, dict] = {}
        possible: dict[str, dict] = {}
        store_rows: dict[str, dict] = {st: {"store": st, "artifacts": 0, "removed_artifacts": 0, "people": set(),
                                            "kinds": Counter(), "raw_artifacts": 0} for st in stores}

        def add(bucket, pid, et, exposure, art, reason=None):
            row = bucket.setdefault(pid, {"principal_id": pid, "element_types": set(), "artifacts": 0,
                                          "stores": set(), "exposure": exposure, "reasons": set(),
                                          "mentioned_only": True})
            if et and et not in INTERNAL_TYPES:
                row["element_types"].add(et)
            row["artifacts"] += 1
            row["stores"].add(art.store)
            if ORDER.index(exposure) < ORDER.index(row["exposure"]):
                row["exposure"] = exposure
            if reason:
                row["reasons"].add(reason)

        for a in arts:
            sr = store_rows[a.store]
            removed = a.status == ArtifactStatus.ERASED.value
            sr["removed_artifacts" if removed else "artifacts"] += 1
            sr["kinds"][a.kind] += 1
            sr["raw_artifacts"] += int(bool(a.contains_raw_pii) and not removed)
            direct = by_art.get(a.artifact_id, [])
            owners = self.f.store.owners_of(a.artifact_id) if direct else set()
            for pid, et, _third in direct:
                exposure = self._exposure(a, pstatus(pid), vault_compromised)
                if removed:
                    add(possible, pid, et, exposure, a, "data was in an artifact since erased: check whether it "
                                                        "was removed before the breach")
                    continue
                add(people, pid, et, exposure, a)
                sr["people"].add(pid)
                if pid in owners:
                    people[pid]["mentioned_only"] = False
            if not removed and a.kind in DERIVED_KINDS:
                for pid in self.f.store.principals_behind(a.artifact_id) - {d[0] for d in direct}:
                    add(possible, pid, None, self._exposure(a, pstatus(pid), vault_compromised), a,
                        f"data contributed to a derived {a.kind} in the breached store")

        if vault_compromised:
            notes.append("the vault was compromised: every token for a person whose key is not destroyed should be "
                         "treated as readable, wherever the tokens are")
        for pid in list(possible):
            if pid in people:
                del possible[pid]

        aware_iso = iso(aware_t)
        detailed_due = aware_t + timedelta(hours=int(rules["board_detailed"]["within_hours"]))
        inv_by_conn = {s.get("connector"): s for s in inv_rows if s.get("connector")}
        recipients = {r.store: r for r in self.f.config.rights.recipients}
        stores_out = []
        for st in stores:
            sr, inv = store_rows[st], inv_by_conn.get(st, {})
            rec = recipients.get(st)
            stores_out.append({
                "store": st, "system": inv.get("name"), "platform": inv.get("platform"), "region": inv.get("region"),
                "artifacts": sr["artifacts"], "removed_artifacts": sr["removed_artifacts"],
                "raw_artifacts": sr["raw_artifacts"], "kinds": dict(sr["kinds"]), "people": len(sr["people"]),
                "processor": inv.get("processor") or (rec.name if rec and rec.role == "processor" else None),
                "processor_contract": inv.get("processor_contract"),
                "tracked": bool(sr["artifacts"] or sr["removed_artifacts"]),
            })
            if not (sr["artifacts"] or sr["removed_artifacts"]):
                notes.append(f"store '{st}' has no lineage records up to {iso(end_t)}: affected people cannot be "
                             "listed from the framework; use the store's own access logs and records")
        untracked = [{"system": s["name"], "platform": s.get("platform"), "region": s.get("region"),
                      "processor": s.get("processor"), "data_elements": s.get("data_elements") or [],
                      "reason": "no connector" if not s.get("connector") else None}
                     for s in inv_rows if not s.get("connector")]
        for u in untracked:
            notes.append(f"system '{u['system']}' has no connector, so the framework holds no records of whose data "
                         "is in it: identify affected people from the system itself")

        def finish(rows: dict) -> list[dict]:
            out = []
            for pid in sorted(rows):
                r = rows[pid]
                st = pstatus(pid)
                contact = st != PrincipalStatus.ERASED.value and any(
                    e.element_type in CONTACT_TYPES for e in self.f.store.elements_for(pid))
                out.append({"principal_id": pid, "status": st, "exposure": r["exposure"],
                            "element_types": sorted(r["element_types"]), "artifacts": r["artifacts"],
                            "stores": sorted(r["stores"]), "mentioned_only": r["mentioned_only"],
                            "contact_on_record": contact, "reasons": sorted(r["reasons"])})
            return out

        affected, maybe = finish(people), finish(possible)
        exposure_counts = Counter(p["exposure"] for p in affected)
        type_counts = Counter(t for p in affected for t in p["element_types"])
        bid = breach_id or new_id("brc")
        report = {
            "breach_id": bid, "assessed_at": iso(now), "assessed_by": assessed_by,
            "basis": rules["basis"], "threshold": rules.get("threshold"),
            "rule_set": {"id": rs.id, "version": rs.version, "sha256": rs.sha256},
            "nature": nature,
            "window": {"start": iso(start_t), "end": iso(end_t), "end_known": end is not None},
            "aware_at": aware_iso, "vault_compromised": bool(vault_compromised),
            "deadlines": {
                "principals": {"when": rules["principals"]["when"], "basis": rules["principals"]["basis"]},
                "board_initial": {"when": rules["board_initial"]["when"], "basis": rules["board_initial"]["basis"]},
                "board_detailed": {"due_by": iso(detailed_due), "within_hours": rules["board_detailed"]["within_hours"],
                                   "extendable": bool(rules["board_detailed"].get("extendable")),
                                   "basis": rules["board_detailed"]["basis"]},
            },
            "totals": {"affected": len(affected), "possibly_affected": len(maybe),
                       "artifacts": sum(s["artifacts"] for s in stores_out),
                       "by_exposure": {k: exposure_counts.get(k, 0) for k in ORDER},
                       "by_element_type": dict(sorted(type_counts.items())),
                       "without_contact_on_record": sum(not p["contact_on_record"] for p in affected),
                       "already_erased": sum(p["status"] == PrincipalStatus.ERASED.value for p in affected)},
            "stores": stores_out, "untracked_systems": untracked,
            "affected": affected, "possibly_affected": maybe, "notes": notes,
        }
        sha = hashlib.sha256(_canon(report)).hexdigest()
        signer = self.f.orchestrator.signer
        sig = None
        if signer is not None:
            from ..security.signing import b64
            sig = b64(signer.sign(bytes.fromhex(sha)))
        aid = new_id("bra")

        def utc(dt):                        # SQLite drops offsets; store UTC so every database reads back the same
            return dt.astimezone(timezone.utc) if dt else None

        self.f.store.add_breach_assessment({
            "assessment_id": aid, "breach_id": bid, "assessed_at": utc(now), "assessed_by": assessed_by,
            "aware_at": utc(aware_t), "window_start": utc(start_t), "window_end": utc(end_t), "stores": stores,
            "rule_set": rs.id, "rule_version": rs.version, "rule_sha256": rs.sha256,
            "report": report, "report_sha256": sha, "signature": sig, "signer": getattr(signer, "key_id", None)})
        return report | {"assessment_id": aid, "report_sha256": sha, "signed": bool(sig)}

    @staticmethod
    def _exposure(a, status: str, vault_compromised: bool) -> str:
        if a.contains_raw_pii:
            return "raw"
        if status == PrincipalStatus.ERASED.value:
            return "key_destroyed"
        return "tokens_readable" if vault_compromised else "tokens"

    def _inventory(self, systems: list[str], stores: list[str], notes: list[str]) -> list[dict]:
        """Inventory rows for the named systems and for systems whose connector is a named store."""
        path = self.f.config.rights.inventory_path
        if not path:
            if systems:
                raise BreachError("systems were named but rights.inventory_path is not set")
            notes.append("rights.inventory_path is not set: processors, regions and untracked systems are not shown")
            return []
        from ..delivery.inventory import Inventory

        inv = Inventory.load(path)
        names = {s.name: s for s in inv.systems}
        missing = [n for n in systems if n not in names]
        if missing:
            raise BreachError(f"not in the inventory: {', '.join(missing)}")
        chosen = {n: names[n] for n in systems}
        for s in inv.systems:
            if s.connector and s.connector in stores:
                chosen.setdefault(s.name, s)
        return [s.model_dump(mode="json") for s in chosen.values()]

    # ---- read -----------------------------------------------------------------------------------------------
    def get(self, breach_id: str) -> dict:
        """The latest assessment of a breach, with the history of earlier ones."""
        rows = self.f.store.breach_assessments(breach_id)
        if not rows:
            raise BreachError(f"unknown breach {breach_id}")
        last = rows[-1]
        return last["report"] | {"assessment_id": last["assessment_id"], "report_sha256": last["report_sha256"],
                                 "signed": bool(last["signature"]),
                                 "history": [{"assessment_id": r["assessment_id"], "assessed_at": iso(r["assessed_at"]),
                                              "assessed_by": r["assessed_by"],
                                              "affected": r["report"]["totals"]["affected"]} for r in rows]}

    def list(self) -> list[dict]:
        latest: dict[str, dict] = {}
        for r in self.f.store.breach_assessments():
            latest[r["breach_id"]] = r
        return [{"breach_id": b, "assessed_at": r["report"]["assessed_at"], "aware_at": r["report"]["aware_at"],
                 "stores": r["stores"], "affected": r["report"]["totals"]["affected"],
                 "board_detailed_due_by": r["report"]["deadlines"]["board_detailed"]["due_by"]}
                for b, r in latest.items()]

    def verify(self, breach_id: str) -> dict:
        """Recompute each stored assessment's hash and check its signature."""
        from ..security.signing import unb64

        signer, out = self.f.orchestrator.signer, []
        for r in self.f.store.breach_assessments(breach_id):
            sha = hashlib.sha256(_canon(r["report"])).hexdigest()
            sig_ok = (signer.verify(bytes.fromhex(sha), unb64(r["signature"]))
                      if r["signature"] and signer is not None else None)
            out.append({"assessment_id": r["assessment_id"], "hash_ok": sha == r["report_sha256"],
                        "signature_ok": sig_ok})
        if not out:
            raise BreachError(f"unknown breach {breach_id}")
        return {"breach_id": breach_id, "ok": all(x["hash_ok"] and x["signature_ok"] is not False for x in out),
                "assessments": out}

    # ---- outputs --------------------------------------------------------------------------------------------
    def drafts(self, breach_id: str) -> dict:
        """Draft Board intimations (initial and detailed) and one notice per affected Data Principal."""
        from .render import board_detailed, board_initial, principal_notices

        rep = self.get(breach_id)
        rules = self.f.rights.rules(_when(rep["aware_at"], "aware_at")).breach()
        contact = self.f.config.rights.contact
        return {"board_initial": board_initial(rep, rules, contact),
                "board_detailed": board_detailed(rep, rules, contact),
                "notices": principal_notices(rep, rules, contact)}

    def export(self, breach_id: str, path: str | None = None) -> dict:
        """Signed bundle: report.json, board-initial.md, board-detailed.md, notices.jsonl, summary.md."""
        from ..evidence.bundle import write_signed_zip
        from .render import summary_markdown

        rep, d = self.get(breach_id), self.drafts(breach_id)
        files = {
            "report.json": json.dumps(rep, indent=2, sort_keys=True, default=str).encode(),
            "summary.md": summary_markdown(rep).encode(),
            "board-initial.md": d["board_initial"].encode(),
            "board-detailed.md": d["board_detailed"].encode(),
            "notices.jsonl": "".join(json.dumps(n, ensure_ascii=False) + "\n" for n in d["notices"]).encode(),
        }
        data, manifest = write_signed_zip(path, files, {"kind": "breach", "breach_id": breach_id,
                                                     "assessment_id": rep["assessment_id"]},
                                       signer=self.f.orchestrator.signer)
        return {"breach_id": breach_id, "path": path, "files": sorted(files), "manifest": manifest, "data": data}

