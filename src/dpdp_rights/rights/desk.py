"""Rights desk: one intake and case workflow for every Data Principal right.

    access              Act s.11      summary of data, processing, recipients; reviewed, then released
    correction          s.12(1)-(2)   correct / complete a value; reviewed, then applied through the vault
    erasure, withdrawal s.12(3), s.6  routed to the erasure orchestrator; status mirrored here
    nomination          s.14          register or revoke a nominee
    nominee_invocation  s.14          a nominee asks to act after death or incapacity; reviewed
    grievance           s.13, r.14(3) acknowledged, then resolved or rejected within the published period

Personal data in a case (new values, free text, nominee details) is stored as vault tokens of the
principal, so it is readable only through the vault and is crypto-shredded with the principal's key.
Every state change is an event in a hash-chained, signed log per case.
"""
from __future__ import annotations

import hashlib
import json
from datetime import timedelta
from typing import Any

from ..core.models import new_id, utcnow
from ..evidence.case import aware, canonical, event_hash, iso, verify_events
from . import rules as rulesmod

NOTE = "RIGHTS_NOTE"     # element type for free text a principal or the DPO writes in a rights case
OPEN = ("received", "in_review", "acknowledged")
CLOSED = ("fulfilled", "rejected", "failed")
GRIEVANCE_CATEGORIES = ("request_handling", "consent", "data_accuracy", "security_concern", "notice",
                        "nominee", "other")
IDENTIFIER_TYPES = {"EMAIL", "PHONE_IN", "PHONE", "PAN", "AADHAAR", "UPI_ID"}


class RightsError(ValueError):
    """A rights request or decision was refused (wrong state, not allowed, missing information)."""


def case_anchor(case_id: str) -> str:
    return hashlib.sha256(f"dpdp-rights:rights-case:{case_id}".encode()).hexdigest()


class RightsDesk:
    def __init__(self, dpdp):
        self.f = dpdp
        self.store, self.vault = dpdp.store, dpdp.vault
        self.cfg = dpdp.config.rights

    # ---- rules --------------------------------------------------------------
    def rules(self, on=None) -> rulesmod.RuleSet:
        rs, _ = rulesmod.resolve(self.cfg.rule_set, on, self.cfg.overrides, self.cfg.rule_sets_dir)
        return rs

    def _rules_for_case(self, case: dict) -> rulesmod.RuleSet:
        return self.rules(aware(case["received_at"]))

    def review_required(self, rtype: str, rs: rulesmod.RuleSet | None = None) -> bool:
        if self.cfg.review_required is not None:
            return rtype in self.cfg.review_required
        return bool((rs or self.rules()).request(rtype).get("review_by_default"))

    # ---- intake -------------------------------------------------------------
    def submit(self, rtype: str, principal_id: str, *, requested_by: str, verified_by: str | None = None,
               verification_ref: str | None = None, channel: str = "api", on_behalf_of: str | None = None,
               idempotency_key: str | None = None, **details: Any) -> dict:
        if idempotency_key:
            prev = self.store.rights_case_by_key(idempotency_key)
            if prev:
                return self._summary(prev) | {"duplicate": True}
        if rtype not in rulesmod.REQUEST_TYPES:
            raise RightsError(f"type must be one of {', '.join(rulesmod.REQUEST_TYPES)}")
        if self.store.get_principal(principal_id) is None:
            raise KeyError("unknown data principal")
        rs = self.rules()
        rule = rs.request(rtype)
        acting = "nominee" if on_behalf_of else "principal"
        if acting not in rule.get("requesters", []):
            raise RightsError(f"a {acting} cannot make a {rtype} request under {rs.id} {rs.version}")
        if on_behalf_of:
            nom = self.store.get_nomination(on_behalf_of)
            if not nom or nom["principal_id"] != principal_id:
                raise RightsError("unknown nomination for this data principal")
            if rtype != "nominee_invocation" and nom["status"] != "invoked":
                raise RightsError("the nominee can act only after the nomination has been invoked and approved")
        now = utcnow()
        case_id = new_id("rc")
        row = {"case_id": case_id, "type": rtype, "principal_id": principal_id, "status": "received",
               "channel": channel, "requested_by": requested_by, "verified_by": verified_by,
               "verification_ref": verification_ref, "on_behalf_of": on_behalf_of, "received_at": now,
               "due_by": now + timedelta(days=rs.due_days(rtype)), "idempotency_key": idempotency_key,
               **rs.ref(), "details": {}, "outcome": {}}
        handler = getattr(self, f"_intake_{rtype}")
        row["details"] = handler(principal_id, row, details)
        self.store.add_rights_case(row)
        self._event(case_id, "received", requested_by, {"type": rtype, "channel": channel, "on_behalf_of": on_behalf_of,
                                                        "verified_by": verified_by, "verification_ref": verification_ref,
                                                        **rs.ref()})
        self._notify("rights_case_received", self.store.get_rights_case(case_id))
        getattr(self, f"_after_intake_{rtype}", lambda c, rs: None)(self.store.get_rights_case(case_id), rs)
        return self._summary(self.store.get_rights_case(case_id))

    def _tok(self, pid: str, etype: str, value: str | None) -> str | None:
        return self.vault.tokenize(pid, etype, value) if value else None

    # access ------------------------------------------------------------------
    def _intake_access(self, pid, row, d):
        return {}

    def _after_intake_access(self, case, rs):
        from .access import build_access_report

        report, review_notes = build_access_report(self.f, case["principal_id"], rs)
        self.store.update_rights_case(case["case_id"], outcome={"report": report, "review_notes": review_notes})
        self._event(case["case_id"], "report_prepared", "system",
                    {"report_sha256": _sha(report), "review_notes": len(review_notes)})
        if self.review_required("access", rs):
            self._status(case["case_id"], "in_review", "system")
        else:
            self._close(case["case_id"], "fulfilled", "system", {"released": True})

    # correction --------------------------------------------------------------
    def _intake_correction(self, pid, row, d):
        etype = (d.get("element_type") or "").upper()
        action = {"update": "correct"}.get(d.get("action", "correct"), d.get("action", "correct"))
        new_value = d.get("new_value")
        if not etype or not new_value:
            raise RightsError("correction needs element_type and new_value")
        if action not in ("correct", "complete"):
            raise RightsError("action must be correct, update or complete")
        target = d.get("ref")
        if action == "correct":
            mine = [t for t in self.vault.tokens_for(pid) if self.vault.element_type_of(t) == etype]
            if target:
                if target not in mine:
                    raise RightsError("ref is not one of this person's values of that type")
            elif len(mine) == 1:
                target = mine[0]
            elif not mine:
                raise RightsError(f"no {etype} value on record to correct; use action=complete to add one")
            else:
                raise RightsError(f"{len(mine)} {etype} values on record; say which one with ref "
                                  "(the access report lists each value's ref)")
        return {"element_type": etype, "action": action, "ref": target,
                "new_value": self._tok(pid, NOTE, new_value), "reason": self._tok(pid, NOTE, d.get("reason"))}

    def _after_intake_correction(self, case, rs):
        if self.review_required("correction", rs):
            self._status(case["case_id"], "in_review", "system")
        else:
            self._apply_correction(case, "system")

    def _apply_correction(self, case: dict, actor: str) -> None:
        d, pid = case["details"], case["principal_id"]
        new_value = self.vault.detokenize(d["new_value"])
        if new_value is None:
            raise RightsError("the requested value is no longer readable (principal erased?)")
        out: dict[str, Any] = {"action": d["action"], "element_type": d["element_type"]}
        if d["action"] == "correct":
            res = self.vault.correct(d["ref"], new_value)
            out["ref"] = d["ref"]
            out["surrogate"] = res["surrogate"]
            token = d["ref"]
        else:
            token = self.vault.tokenize(pid, d["element_type"], new_value)
            self.f._element(pid, d["element_type"], token)
            out["ref"] = token
        if d["element_type"] in IDENTIFIER_TYPES:
            self.vault.link_identifier(pid, d["element_type"], new_value)
        # Copies that hold the token now read the corrected value. Copies written before tokenisation, and
        # recipients holding the data, need follow-up outside the vault.
        follow_up, recipients = [], {r.store: r for r in self.cfg.recipients}
        for e in self.store.downstream(pid):
            a = e["artifact"]
            if a.status in ("erased",):
                continue
            if token in self.store.tokens_in_artifact_for(a.artifact_id, pid) or a.contains_raw_pii:
                if a.contains_raw_pii:
                    follow_up.append({"store": a.store, "artifact_id": a.artifact_id,
                                      "action": "correct by hand (stored before tokenisation)"})
                if a.store in recipients:
                    follow_up.append({"store": a.store, "artifact_id": a.artifact_id,
                                      "action": f"inform {recipients[a.store].name} of the correction"})
        out["follow_up"] = follow_up
        self._close(case["case_id"], "fulfilled", actor, out)

    # erasure / withdrawal ----------------------------------------------------
    def _intake_erasure(self, pid, row, d):
        r = self.f.submit_request(pid, scope=d.get("scope", "full"), requested_by=row["requested_by"],
                                  verified_by=row["verified_by"], verification_ref=row["verification_ref"],
                                  requested_via=row["channel"])
        row["erasure_request_id"], row["due_by"] = r["request_id"], aware(self.store.get_request(r["request_id"])["due_by"])
        return {"scope": d.get("scope", "full")}

    def _intake_withdrawal(self, pid, row, d):
        if not d.get("purpose_id"):
            raise RightsError("withdrawal needs purpose_id")
        r = self.f.submit_request(pid, withdraw_purpose=d["purpose_id"], requested_by=row["requested_by"],
                                  verified_by=row["verified_by"], verification_ref=row["verification_ref"],
                                  requested_via=row["channel"])
        row["erasure_request_id"], row["due_by"] = r["request_id"], aware(self.store.get_request(r["request_id"])["due_by"])
        return {"purpose_id": d["purpose_id"]}

    def _sync_erasure(self, case: dict) -> dict:
        if case["type"] not in ("erasure", "withdrawal") or case["status"] in CLOSED or not case["erasure_request_id"]:
            return case
        r = self.store.get_request(case["erasure_request_id"]) or {}
        st = r.get("status", "")
        if st.startswith("completed"):
            self._close(case["case_id"], "fulfilled", "system", {"erasure_status": st,
                                                                  "certificate": (self.store.get_certificate(r["request_id"]) or {}).get("sha256")})
        elif st == "failed":
            self._close(case["case_id"], "failed", "system", {"erasure_status": st})
        elif st and case["status"] == "received":
            self._status(case["case_id"], "in_review", "system", {"erasure_status": st})
        return self.store.get_rights_case(case["case_id"])

    # nomination --------------------------------------------------------------
    def _intake_nomination(self, pid, row, d):
        if d.get("action") == "revoke":
            nom = self.store.get_nomination(d.get("nomination_id") or "")
            if not nom or nom["principal_id"] != pid:
                raise RightsError("unknown nomination for this data principal")
            if nom["status"] == "revoked":
                raise RightsError("nomination already revoked")
            return {"action": "revoke", "nomination_id": nom["nomination_id"]}
        events = d.get("events", "both")
        if events not in ("death", "incapacity", "both"):
            raise RightsError("events must be death, incapacity or both")
        if not d.get("nominee_name") or not d.get("nominee_contact"):
            raise RightsError("nomination needs nominee_name and nominee_contact")
        return {"action": "nominate", "events": events, "relationship": d.get("relationship"),
                "nominee_name": self._tok(pid, "NAME", d["nominee_name"]),
                "nominee_contact": self._tok(pid, NOTE, d["nominee_contact"])}

    def _after_intake_nomination(self, case, rs):
        d, now = case["details"], utcnow()
        if d["action"] == "revoke":
            self.store.update_nomination(d["nomination_id"], status="revoked", revoked_at=now)
            self._close(case["case_id"], "fulfilled", "system", {"nomination_id": d["nomination_id"], "revoked": True})
            return
        nid = new_id("nom")
        self.store.add_nomination({"nomination_id": nid, "principal_id": case["principal_id"],
                                   "nominee_name": d["nominee_name"], "nominee_contact": d["nominee_contact"],
                                   "relationship": d.get("relationship"), "events": d["events"],
                                   "status": "active", "created_at": now})
        self._close(case["case_id"], "fulfilled", "system", {"nomination_id": nid})

    def _intake_nominee_invocation(self, pid, row, d):
        nom = self.store.get_nomination(row["on_behalf_of"] or "")
        if not nom:
            raise RightsError("a nominee invocation must name the nomination (on_behalf_of)")
        if nom["status"] != "active":
            raise RightsError(f"nomination is {nom['status']}")
        event = d.get("event")
        if event not in ("death", "incapacity") or nom["events"] not in (event, "both"):
            raise RightsError(f"this nomination covers {nom['events']}; event must match")
        if not d.get("evidence_ref"):
            raise RightsError("evidence_ref is required (e.g. the verified death-certificate or medical-record reference)")
        return {"nomination_id": nom["nomination_id"], "event": event, "evidence_ref": d["evidence_ref"]}

    def _after_intake_nominee_invocation(self, case, rs):
        if self.review_required("nominee_invocation", rs):
            self._status(case["case_id"], "in_review", "system")
        else:
            self._invoke(case, "system")

    def _invoke(self, case: dict, actor: str) -> None:
        nid = case["details"]["nomination_id"]
        self.store.update_nomination(nid, status="invoked", invoked_at=utcnow(), invocation_case_id=case["case_id"])
        self._close(case["case_id"], "fulfilled", actor, {"nomination_id": nid, "nominee_may_act": True})

    # grievance ---------------------------------------------------------------
    def _intake_grievance(self, pid, row, d):
        cat = d.get("category", "other")
        if cat not in GRIEVANCE_CATEGORIES:
            raise RightsError(f"category must be one of {', '.join(GRIEVANCE_CATEGORIES)}")
        if not d.get("description"):
            raise RightsError("grievance needs a description")
        related = d.get("related_case_id")
        if related and not (self.store.get_rights_case(related) or self.store.get_request(related)):
            raise RightsError("related_case_id is not a known rights case or erasure request")
        return {"category": cat, "description": self._tok(pid, NOTE, d["description"]), "related_case_id": related}

    # ---- decisions and responses -------------------------------------------
    def decide(self, case_id: str, actor: str, decision: str, reason: str | None = None) -> dict:
        """Approve or reject a case waiting for review (access, correction, nominee invocation)."""
        case = self._get(case_id)
        if case["status"] != "in_review" or case["type"] not in ("access", "correction", "nominee_invocation"):
            raise RightsError(f"{case['type']} case is {case['status']}; nothing to decide")
        if actor == case["requested_by"]:
            raise RightsError("the person who submitted the request cannot decide it")
        if decision not in ("approve", "reject"):
            raise RightsError("decision must be approve or reject")
        if decision == "reject":
            if not reason:
                raise RightsError("a rejection needs a reason the Data Principal can read")
            self._close(case_id, "rejected", actor, {"reason": self._tok(case["principal_id"], NOTE, reason)})
        elif case["type"] == "access":
            self._close(case_id, "fulfilled", actor, {"released": True})
        elif case["type"] == "correction":
            self._apply_correction(case, actor)
        else:
            self._invoke(case, actor)
        return self.view(case_id)

    def respond(self, case_id: str, actor: str, status: str, response: str | None = None) -> dict:
        """Grievances: acknowledge, then resolve (fulfilled) or reject, with a response to the principal."""
        case = self._get(case_id)
        if case["type"] != "grievance":
            raise RightsError("respond is for grievances; use decide for other cases")
        if case["status"] in CLOSED:
            raise RightsError(f"grievance is already {case['status']}")
        if actor == case["requested_by"]:
            raise RightsError("the person who raised the grievance cannot respond to it")
        if status not in ("acknowledged", "fulfilled", "rejected"):
            raise RightsError("status must be acknowledged, fulfilled or rejected")
        tok = self._tok(case["principal_id"], NOTE, response)
        if status == "acknowledged":
            self._status(case_id, "acknowledged", actor, {"response": tok})
        else:
            if not response:
                raise RightsError("closing a grievance needs a response the Data Principal can read")
            rs = self._rules_for_case(case)
            self._close(case_id, status, actor, {"response": tok, "board_escalation": rs.data.get("board_escalation")})
        return self.view(case_id)

    # ---- reading ------------------------------------------------------------
    def view(self, case_id: str, reveal: str = "none", for_principal: str | None = None) -> dict:
        """A case with its events. reveal: none (tokens), masked, full (the principal or the DPO)."""
        case = self._sync_erasure(self._get(case_id))
        out = self._summary(case)
        out["details"] = self._reveal(case["details"] or {}, case["principal_id"], reveal)
        outcome = {k: v for k, v in (case["outcome"] or {}).items() if k != "report"}
        if for_principal:
            outcome.pop("review_notes", None)
        out["outcome"] = self._reveal(outcome, case["principal_id"], reveal)
        out["events"] = [{k: e[k] for k in ("kind", "actor", "at")} | {"body": e["body"]} for e in self.events(case_id)]
        out["integrity"] = self.verify_chain(case_id)
        if case["on_behalf_of"]:
            out["on_behalf_of"] = case["on_behalf_of"]
        return out

    def list(self, **filters) -> list[dict]:
        overdue = filters.pop("overdue", False)
        rows = [self._summary(self._sync_erasure(c)) for c in self.store.rights_cases(**filters)]
        return [r for r in rows if r["overdue"]] if overdue else rows

    def access_report(self, case_id: str, values: str | None = None) -> dict:
        case = self._get(case_id)
        if case["type"] != "access":
            raise RightsError("not an access case")
        if case["status"] != "fulfilled":
            raise RightsError(f"access report is not released (case is {case['status']})")
        from .access import render_values

        return render_values(self.vault, case["outcome"]["report"], case["principal_id"], values or self.cfg.access_values)

    def nominations(self, principal_id: str) -> list[dict]:
        return [{k: (iso(v) if hasattr(v, "isoformat") else v) for k, v in n.items()}
                for n in self.store.nominations_for(principal_id)]

    def events(self, case_id: str, raw: bool = False) -> list[dict]:
        out = []
        for e in self.store.rights_events_for(case_id):
            ev = {"event_id": e["event_id"], "kind": e["kind"], "actor": e["actor"], "at": iso(e["at"]),
                  "body": json.loads(e["body"]), "prev_sha256": e["prev_sha256"], "sha256": e["sha256"],
                  "signature": e["signature"], "signer": e["signer"]}
            if raw:
                ev["_raw"] = e["body"]
            out.append(ev)
        return out

    def verify_chain(self, case_id: str) -> dict:
        return verify_events(case_id, self.events(case_id, raw=True), [case_anchor(case_id)],
                             self.f.orchestrator.signer)

    def sla_counts(self, due_soon_days: int = 7) -> dict[str, dict[str, int]]:
        now, out = utcnow(), {}
        for c in self.store.rights_cases():
            if c["status"] in CLOSED:
                continue
            days = (aware(c["due_by"]) - now).total_seconds() / 86400
            b = out.setdefault(c["type"], {"ok": 0, "due_soon": 0, "overdue": 0})
            b["overdue" if days < 0 else "due_soon" if days <= due_soon_days else "ok"] += 1
        return out

    # ---- internals ----------------------------------------------------------
    def _get(self, case_id: str) -> dict:
        c = self.store.get_rights_case(case_id)
        if not c:
            raise KeyError("unknown rights case")
        return c

    def _summary(self, c: dict) -> dict:
        now = utcnow()
        due, closed = aware(c["due_by"]), aware(c["closed_at"])
        return {"case_id": c["case_id"], "type": c["type"], "status": c["status"], "principal_id": c["principal_id"],
                "channel": c["channel"], "requested_by": c["requested_by"], "verified_by": c["verified_by"],
                "verification_ref": c["verification_ref"], "received_at": iso(c["received_at"]), "due_by": iso(due),
                "closed_at": iso(closed), "erasure_request_id": c["erasure_request_id"],
                "rules": {"rule_set": c["rule_set"], "rule_version": c["rule_version"], "rule_sha256": c["rule_sha256"]},
                "within_due": (closed <= due) if closed else None,
                "overdue": c["status"] not in CLOSED and now > due}

    def _reveal(self, obj: Any, pid: str, mode: str) -> Any:
        if mode == "none":
            return obj
        if isinstance(obj, dict):
            return {k: self._reveal(v, pid, mode) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self._reveal(v, pid, mode) for v in obj]
        if isinstance(obj, str) and self.vault.find_tokens(obj):
            return self.vault.reveal(obj, {pid}, masked=(mode == "masked"))
        return obj

    def _status(self, case_id: str, status: str, actor: str, body: dict | None = None) -> None:
        self.store.update_rights_case(case_id, status=status)
        self._event(case_id, status, actor, body or {})

    def _close(self, case_id: str, status: str, actor: str, outcome: dict) -> None:
        case = self._get(case_id)
        merged = (case["outcome"] or {}) | outcome
        self.store.update_rights_case(case_id, status=status, closed_at=utcnow(), outcome=merged)
        self._event(case_id, status, actor, {k: v for k, v in outcome.items() if k != "report"})
        self._notify("rights_case_closed", self._get(case_id))

    def _event(self, case_id: str, kind: str, actor: str, body: dict) -> None:
        prior = self.store.rights_events_for(case_id)
        prev = prior[-1]["sha256"] if prior else case_anchor(case_id)
        at = utcnow()
        text = canonical(body | {"at": at.isoformat()})
        eid = new_id("re")
        digest = event_hash(eid, case_id, kind, actor, text, prev)
        sig = signer_id = None
        signer = self.f.orchestrator.signer
        if signer is not None:
            from ..security.signing import b64

            sig, signer_id = b64(signer.sign(digest)), signer.key_id
        self.store.add_rights_event({"event_id": eid, "case_id": case_id, "kind": kind, "actor": actor, "body": text,
                                     "at": at, "prev_sha256": prev, "sha256": digest.hex(), "signature": sig,
                                     "signer": signer_id})

    def _notify(self, event: str, case: dict) -> None:
        self.f.notifications.emit(event, {"case_id": case["case_id"], "type": case["type"], "status": case["status"],
                                          "principal_id": case["principal_id"], "due_by": iso(aware(case["due_by"]))})


def _sha(obj) -> str:
    return hashlib.sha256(canonical(obj).encode()).hexdigest()
