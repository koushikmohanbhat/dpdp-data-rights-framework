"""Case record per request: an append-only, hash-chained case log plus everything an
auditor needs to see about one erasure or withdrawal request.

The case log holds two kinds of event:

* ``manual_action`` - something a person did outside the framework (a system with no connector,
  a processor instructed by email, a paper file destroyed), with a ticket or change reference.
* ``review`` - a reviewer's decision (approved / rejected / needs_info) against a checklist.

Each event's SHA-256 covers the previous event's hash; the first event is anchored to the
request's certificate (or to the request itself when there is no certificate). Events are signed
with the certificate signer when one is configured. Nothing in a case record is personal data:
principals are pseudonymous IDs, stores hold tokens, and free text is checked by the PII detector
before it is accepted (``evidence.reject_personal_data``).
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from ..core.config import EvidenceConfig
from ..core.models import new_id, utcnow
from ..vault.vault import TOKEN_RE

SCHEMA = "dpdp-rights/case/v1"
TERMINAL = ("completed", "completed_with_exceptions", "failed")
DECISIONS = ("approved", "rejected", "needs_info")
MANUAL_ACTIONS = ("deleted", "redacted", "retained", "processor_instructed", "processor_confirmed",
                  "not_applicable", "other")


class EvidenceError(ValueError):
    """A case-log entry was refused (wrong state, separation of duties, personal data in text...)."""


def canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, default=str, separators=(",", ":"), ensure_ascii=False)


def aware(dt):
    if dt is None or isinstance(dt, str):
        return dt
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def iso(dt) -> str | None:
    dt = aware(dt)
    return dt.isoformat() if isinstance(dt, datetime) else dt


def request_anchor(request_id: str) -> str:
    return hashlib.sha256(f"dpdp-rights:request:{request_id}".encode()).hexdigest()


def event_hash(event_id: str, request_id: str, kind: str, actor: str, body: str, prev: str) -> bytes:
    return hashlib.sha256(canonical({"event_id": event_id, "request_id": request_id, "kind": kind,
                                     "actor": actor, "body": body, "prev_sha256": prev}).encode()).digest()


class CaseLog:
    def __init__(self, store, signer, cfg: EvidenceConfig, detector=None, notifications=None):
        self.store, self.signer, self.cfg = store, signer, cfg
        self.detector, self.notifications = detector, notifications

    # ---- writing ----------------------------------------------------------
    def record_manual_action(self, request_id: str, actor: str, *, system: str, action: str, reference: str,
                             notes: str | None = None, performed_at: str | None = None) -> dict:
        """Record work done outside the framework (systems with no connector, processor instructions)."""
        r = self._request(request_id)
        if action not in MANUAL_ACTIONS:
            raise EvidenceError(f"action must be one of {', '.join(MANUAL_ACTIONS)}")
        if not reference or not reference.strip():
            raise EvidenceError("reference is required (ticket, change or case number)")
        self._no_personal_data(system=system, reference=reference, notes=notes)
        body = {"system": system, "action": action, "reference": reference, "notes": notes,
                "performed_at": performed_at or utcnow().isoformat(), "scope": r["scope"]}
        return self._append(request_id, "manual_action", actor, body)

    def record_review(self, request_id: str, reviewer: str, *, decision: str, checklist: dict[str, Any] | None = None,
                      notes: str | None = None, role: str = "reviewer") -> dict:
        """Record a reviewer's decision. Separation of duties: the reviewer cannot be the requester or
        anyone who recorded a manual action on this case."""
        r = self._request(request_id)
        if r["status"] not in TERMINAL:
            raise EvidenceError(f"request is {r['status']}; review after processing has finished")
        if decision not in DECISIONS:
            raise EvidenceError(f"decision must be one of {', '.join(DECISIONS)}")
        if reviewer == r.get("requested_by"):
            raise EvidenceError("a reviewer cannot sign off a request they submitted")
        events = self.store.case_events_for(request_id)
        if any(e["kind"] == "manual_action" and e["actor"] == reviewer for e in events):
            raise EvidenceError("a reviewer cannot sign off a case where they recorded manual actions")
        checklist = dict(checklist or {})
        known = {c.id for c in self.cfg.review_checklist}
        unknown = set(checklist) - known
        if unknown:
            raise EvidenceError(f"unknown checklist items: {', '.join(sorted(unknown))}")
        for k, v in checklist.items():
            if v not in (True, False, "n/a"):
                raise EvidenceError(f"checklist item {k} must be true, false or 'n/a'")
        self._no_personal_data(notes=notes)
        if decision == "approved":
            if r["status"] == "failed":
                raise EvidenceError("a failed request cannot be approved; fix the cause and re-run it")
            missing = known - set(checklist)
            if missing:
                raise EvidenceError(f"approval needs every checklist item answered; missing: {', '.join(sorted(missing))}")
            if any(v is False for v in checklist.values()):
                raise EvidenceError("approval with a failed checklist item is not allowed; use needs_info or rejected")
            cert = self._certificate_body(request_id)
            # the Rule 8(3) identifier escrow is routine and configured; anything else needs a written basis
            unusual = [e for e in cert.get("exceptions", []) if e.get("kind") != "retention_escrow"]
            has_exceptions = bool(unusual or cert.get("failures")) or r["status"] != "completed"
            if has_exceptions and not (notes and notes.strip()):
                raise EvidenceError("notes are required to approve a case with exceptions or failures")
        elif not (notes and notes.strip()):
            raise EvidenceError(f"notes are required for {decision}")
        body = {"decision": decision, "checklist": checklist, "notes": notes, "role": role,
                "request_status": r["status"]}
        ev = self._append(request_id, "review", reviewer, body)
        state = self.sign_off(request_id)
        if self.notifications is not None:
            self.notifications.emit("case_reviewed", {"request_id": request_id, "decision": decision,
                                                      "sign_off": state["state"], "approvals": len(state["approvals"]),
                                                      "required": state["required"]})
        return ev | {"sign_off": state}

    # ---- reading ----------------------------------------------------------
    def events(self, request_id: str, raw: bool = False) -> list[dict]:
        out = []
        for e in self.store.case_events_for(request_id):
            ev = {"event_id": e["event_id"], "kind": e["kind"], "actor": e["actor"], "at": iso(e["at"]),
                  "body": json.loads(e["body"]), "prev_sha256": e["prev_sha256"], "sha256": e["sha256"],
                  "signature": e["signature"], "signer": e["signer"]}
            if raw:
                ev["_raw"] = e["body"]
            out.append(ev)
        return out

    def verify_chain(self, request_id: str) -> dict:
        return verify_events(request_id, self.events(request_id, raw=True), self._anchors(request_id), self.signer)

    def sign_off(self, request_id: str) -> dict:
        return sign_off_state(self.events(request_id), self.cfg.required_approvals,
                              (self.store.get_request(request_id) or {}).get("status"))

    # ---- internals --------------------------------------------------------
    def _request(self, request_id: str) -> dict:
        r = self.store.get_request(request_id)
        if not r:
            raise KeyError("unknown request")
        if r.get("dry_run"):
            raise EvidenceError("dry runs have no case log")
        return r

    def _certificate_body(self, request_id: str) -> dict:
        c = self.store.get_certificate(request_id)
        return json.loads(c["payload"]) if c else {}

    def _anchors(self, request_id: str) -> list[str]:
        c = self.store.get_certificate(request_id)
        return [x for x in ((c or {}).get("sha256"), request_anchor(request_id)) if x]

    def _append(self, request_id: str, kind: str, actor: str, body: dict) -> dict:
        prior = self.store.case_events_for(request_id)
        prev = prior[-1]["sha256"] if prior else self._anchors(request_id)[0]
        at = utcnow()
        body = body | {"at": at.isoformat()}
        text = canonical(body)
        eid = new_id("ce")
        digest = event_hash(eid, request_id, kind, actor, text, prev)
        sig = signer_id = None
        if self.signer is not None:
            from ..security.signing import b64

            sig, signer_id = b64(self.signer.sign(digest)), self.signer.key_id
        self.store.add_case_event({"event_id": eid, "request_id": request_id, "kind": kind, "actor": actor,
                                   "body": text, "at": at, "prev_sha256": prev, "sha256": digest.hex(),
                                   "signature": sig, "signer": signer_id})
        return {"event_id": eid, "kind": kind, "actor": actor, "at": at.isoformat(), "body": body,
                "prev_sha256": prev, "sha256": digest.hex(), "signed": sig is not None}

    def _no_personal_data(self, **fields: str | None) -> None:
        if not self.cfg.reject_personal_data or self.detector is None:
            return
        for name, value in fields.items():
            if not value:
                continue
            found = sorted({e.type for e in self.detector.detect(value) if not TOKEN_RE.fullmatch(e.text)})
            if found:
                raise EvidenceError(f"{name} appears to contain personal data ({', '.join(found)}); "
                                    "case records must hold references (ticket, change, case IDs) only")


def verify_events(request_id: str, events: list[dict], anchors: list[str], signer=None,
                  public_key_pem: str | None = None) -> dict:
    """Recompute every event hash and link. Works on stored events or on a case.json from a bundle."""
    from ..security.signing import unb64, verify_with_public_key

    out = {"ok": True, "events": len(events), "anchored_to": None, "broken_at": None, "signatures_ok": None}
    prev = None
    sig_results = []
    for i, e in enumerate(events):
        expected_prev = prev if i else None
        if i == 0:
            if e["prev_sha256"] not in anchors:
                out.update(ok=False, broken_at=e["event_id"])
                return out
            out["anchored_to"] = "certificate" if len(anchors) > 1 and e["prev_sha256"] == anchors[0] else "request"
        elif e["prev_sha256"] != expected_prev:
            out.update(ok=False, broken_at=e["event_id"])
            return out
        text = e.get("_raw", canonical(e["body"]))       # stored text when checking the database
        digest = event_hash(e["event_id"], request_id, e["kind"], e["actor"], text, e["prev_sha256"])
        if digest.hex() != e["sha256"]:
            out.update(ok=False, broken_at=e["event_id"])
            return out
        if e.get("signature"):
            if public_key_pem:
                sig_results.append(verify_with_public_key(public_key_pem, digest, unb64(e["signature"])))
            elif signer is not None:
                sig_results.append(signer.verify(digest, unb64(e["signature"])))
        prev = e["sha256"]
    if sig_results:
        out["signatures_ok"] = all(sig_results)
        out["ok"] = out["ok"] and out["signatures_ok"]
    return out


def sign_off_state(events: list[dict], required: int, request_status: str | None) -> dict:
    """Latest decision per reviewer wins. Approvals recorded before the last manual action are stale."""
    if required <= 0:
        return {"state": "not_required", "required": 0, "approvals": [], "stale_approvals": []}
    if request_status not in TERMINAL:
        return {"state": "not_reviewable", "required": required, "approvals": [], "stale_approvals": []}
    last_manual = max((i for i, e in enumerate(events) if e["kind"] == "manual_action"), default=-1)
    latest: dict[str, tuple[int, dict]] = {}
    for i, e in enumerate(events):
        if e["kind"] == "review":
            latest[e["actor"]] = (i, e)
    decisions = {a: e["body"]["decision"] for a, (_, e) in latest.items()}
    approvals = [a for a, (i, e) in latest.items() if e["body"]["decision"] == "approved" and i > last_manual]
    stale = [a for a, (i, e) in latest.items() if e["body"]["decision"] == "approved" and i < last_manual]
    if "rejected" in decisions.values():
        state = "rejected"
    elif "needs_info" in decisions.values():
        state = "needs_info"
    elif len(approvals) >= required:
        state = "approved"
    else:
        state = "pending"
    signed_at = None
    if state == "approved":
        signed_at = max(latest[a][1]["at"] for a in approvals)
    return {"state": state, "required": required, "approvals": sorted(approvals), "stale_approvals": sorted(stale),
            "signed_off_at": signed_at}


def build_case(dpdp, request_id: str) -> dict:
    """Everything about one request, for a reviewer or an auditor. No personal data."""
    store = dpdp.store
    r = store.get_request(request_id)
    if not r:
        raise KeyError("unknown request")
    cert = store.get_certificate(request_id)
    body = json.loads(cert["payload"]) if cert else {}
    cases: CaseLog = dpdp.cases
    events = cases.events(request_id)
    now = utcnow()
    due, done, received = aware(r["due_by"]), aware(r["completed_at"]), aware(r["received_at"])
    sla = {"received_at": iso(received), "due_by": iso(due), "completed_at": iso(done),
           "days_taken": round((done - received).total_seconds() / 86400, 2) if done and received else None,
           "met": (done <= due) if done and due else None,
           "open_overdue": bool(due and not done and now > due)}
    actions = [{"artifact_id": a["artifact_id"], "store": a["store"], "action": a["action"], "ok": bool(a["ok"]),
                "executed_at": iso(a["executed_at"]), "detail": a["detail"] or {}}
               for a in store.actions_for(request_id)]
    by_store: dict[str, dict[str, int]] = {}
    for a in actions:
        by_store.setdefault(a["store"], {}).setdefault(a["action"], 0)
        by_store[a["store"]][a["action"]] += 1
    grants = store.grants(r["principal_id"])
    logs = store.access_logs([g["grant_id"] for g in grants])
    timeline = [{"at": iso(received), "event": f"request received via {r['requested_via']}"}]
    if cert:
        timeline.append({"at": iso(cert["issued_at"]), "event": "certificate issued"})
    if done:
        timeline.append({"at": iso(done), "event": f"processing finished: {r['status']}"})
    for e in events:
        what = (f"manual action on {e['body']['system']}: {e['body']['action']} ({e['body']['reference']})"
                if e["kind"] == "manual_action" else f"review by {e['actor']}: {e['body']['decision']}")
        timeline.append({"at": e["at"], "event": what})
    timeline.sort(key=lambda t: t["at"] or "")
    return {
        "schema": SCHEMA,
        "generated_at": now.isoformat(),
        "environment": dpdp.config.environment,
        "tenant": dpdp.config.tenant,
        "request": {k: (iso(v) if isinstance(v, datetime) else v) for k, v in r.items() if k != "idempotency_key"},
        "sla": sla,
        "consents": [{k: (iso(v) if isinstance(v, datetime) else v) for k, v in c.items()}
                     for c in store.consents_for(r["principal_id"])],
        "actions": actions,
        "actions_by_store": by_store,
        "exceptions": body.get("exceptions", []),
        "failures": body.get("failures", []),
        "verification": body.get("verification", []),
        "vault": body.get("vault"),
        "escrow": [{k: (iso(v) if isinstance(v, datetime) else v) for k, v in e.items()}
                   for e in store.escrows(request_id)],
        "certificate": ({"sha256": cert["sha256"], "prev_sha256": cert["prev_sha256"], "issued_at": iso(cert["issued_at"]),
                         "signer": cert["signer"], "signed": bool(cert["signature"]), "archive_uri": cert["archive_uri"],
                         "check": dpdp.verify_certificate(request_id)} if cert else None),
        "break_glass": {"grants": [{k: (iso(v) if isinstance(v, datetime) else v) for k, v in g.items()} for g in grants],
                        "reads_allowed": sum(1 for x in logs if x["outcome"] == "allowed"),
                        "reads_denied": sum(1 for x in logs if x["outcome"] == "denied")},
        "case_log": events,
        "case_log_check": cases.verify_chain(request_id),
        "sign_off": cases.sign_off(request_id),
        "review_checklist": [c.model_dump() for c in dpdp.config.evidence.review_checklist],
        "timeline": timeline,
    }
