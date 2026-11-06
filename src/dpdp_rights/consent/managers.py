"""Consent Managers (Act s.6(7)-(9); Rules r.4 and First Schedule).

A Data Principal can give, manage, review and withdraw consent through a Consent Manager registered with the
Board. This module receives the Consent Manager's events, checks they came from it, and applies them:

- ``given``: consent recorded per mapped purpose and element type, with ``consent_manager_ref`` "<cm>:<artefact>".
  It counts only while the artefact is active and in date.
- ``denied``: recorded in the consent history; nothing is granted.
- ``withdrawn`` / ``expired``: the artefact's consents are withdrawn. If no other consent for the purpose remains,
  a purpose-scoped erasure is queued (``erase_on_withdrawal`` / ``erase_on_expiry``), with the Consent Manager as
  the verified requester and its event id as the reference.

Each event id is applied once (redeliveries return ``duplicate``). Withdrawals made directly with the Fiduciary
are reported back to the Consent Manager the consent came from (``report_url``), best effort and recorded.

**The schema is provisional.** The Board has not published an interoperability standard. The built-in ``generic``
adapter speaks ``dpdp-cm-events/0.1`` (docs/consent-managers.md); a real Consent Manager's API is a plug-in in the
entry point group ``dpdp_rights.consent_managers``: a callable ``(config, opener=None)`` returning an object with
``verify(headers, body)``, ``parse(body) -> list[CmEvent]`` and optionally ``report(payload)``.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import time
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .. import plugins
from ..core.models import utcnow
from .ledger import ConsentDenied

log = logging.getLogger("dpdp_rights.consent_managers")

SCHEMA = "dpdp-cm-events/0.1"
EVENT_TYPES = ("given", "denied", "withdrawn", "expired")
TS_HEADER, SIG_HEADER = "x-cm-timestamp", "x-cm-signature"


class SignatureError(PermissionError):
    """The event was not signed by the configured Consent Manager, or is outside the replay window (HTTP 401)."""


class CmEventError(ValueError):
    """The body does not match the schema (HTTP 422)."""


@dataclass
class CmEvent:
    event_id: str
    type: str                               # given | denied | withdrawn | expired
    artefact_id: str
    principal_ref: str                      # the identifier this Fiduciary knows the principal by
    purposes: list[str]                     # the Consent Manager's purpose codes
    data_items: list[str] = field(default_factory=list)
    notice_version: str | None = None
    valid_until: datetime | None = None
    occurred_at: datetime | None = None
    guardian_id: str | None = None          # for a child or ward: the guardian verified with this Fiduciary


def _dt(v, name: str) -> datetime | None:
    if v in (None, ""):
        return None
    try:
        d = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
    except ValueError as e:
        raise CmEventError(f"{name}: not an ISO 8601 time") from e
    if d.tzinfo is None:
        raise CmEventError(f"{name}: needs a time zone")
    return d


def sign_hmac(secret: str, timestamp: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode(), timestamp.encode() + b"." + body, hashlib.sha256).hexdigest()


class GenericConsentManager:
    """The provisional ``dpdp-cm-events/0.1`` schema, signed with HMAC-SHA256 or Ed25519 over
    ``<timestamp>.<body>`` (headers ``X-CM-Timestamp`` and ``X-CM-Signature``)."""

    def __init__(self, cfg, opener=None, clock=time.time):
        self.cfg, self.v = cfg, cfg.verification
        self._open, self._clock = opener or urllib.request.urlopen, clock

    def _secret(self) -> str | None:
        return self.v.secret or (os.environ.get(self.v.secret_env) if self.v.secret_env else None)

    def _public_key(self):
        from cryptography.hazmat.primitives.serialization import load_pem_public_key

        pem = self.v.public_key_pem
        if not pem and self.v.public_key_path:
            with open(self.v.public_key_path, encoding="utf-8") as fh:
                pem = fh.read()
        if not pem:
            raise SignatureError(f"consent manager '{self.cfg.name}': no public key configured")
        return load_pem_public_key(pem.encode())

    def verify(self, headers: dict[str, str], body: bytes) -> None:
        h = {k.lower(): v for k, v in headers.items()}
        ts, sig = h.get(TS_HEADER), h.get(SIG_HEADER)
        if not ts or not sig:
            raise SignatureError("missing X-CM-Timestamp or X-CM-Signature")
        try:
            age = abs(self._clock() - int(ts))
        except ValueError as e:
            raise SignatureError("X-CM-Timestamp must be Unix seconds") from e
        if age > self.v.replay_window_seconds:
            raise SignatureError("event timestamp is outside the replay window")
        if self.v.mode == "hmac":
            secret = self._secret()
            if not secret:
                raise SignatureError(f"consent manager '{self.cfg.name}': no shared secret configured")
            if not hmac.compare_digest(sign_hmac(secret, ts, body), sig):
                raise SignatureError("signature does not match")
            return
        if not sig.startswith("ed25519="):
            raise SignatureError("expected an ed25519= signature")
        from cryptography.exceptions import InvalidSignature

        try:
            self._public_key().verify(base64.b64decode(sig.removeprefix("ed25519=")), ts.encode() + b"." + body)
        except (InvalidSignature, ValueError) as e:
            raise SignatureError("signature does not match") from e

    def parse(self, body: bytes) -> list[CmEvent]:
        try:
            doc = json.loads(body)
        except ValueError as e:
            raise CmEventError("body is not JSON") from e
        if not isinstance(doc, dict) or doc.get("schema") != SCHEMA:
            raise CmEventError(f"schema must be '{SCHEMA}'")
        if doc.get("consent_manager") != self.cfg.name:
            raise CmEventError(f"consent_manager must be '{self.cfg.name}'")
        events = doc.get("events")
        if not isinstance(events, list) or not events:
            raise CmEventError("events must be a non-empty list")
        out = []
        for i, e in enumerate(events):
            where = f"events[{i}]"
            if not isinstance(e, dict):
                raise CmEventError(f"{where} must be an object")
            art = e.get("artefact") or {}
            for k, v in (("event_id", e.get("event_id")), ("type", e.get("type")), ("artefact.id", art.get("id")),
                         ("artefact.principal_ref", art.get("principal_ref"))):
                if not isinstance(v, str) or not v:
                    raise CmEventError(f"{where}.{k} is required")
            if e["type"] not in EVENT_TYPES:
                raise CmEventError(f"{where}.type must be one of {', '.join(EVENT_TYPES)}")
            purposes = art.get("purposes") or []
            if not isinstance(purposes, list) or not purposes or not all(isinstance(p, str) for p in purposes):
                raise CmEventError(f"{where}.artefact.purposes must be a non-empty list of codes")
            items = art.get("data_items") or []
            if not isinstance(items, list) or not all(isinstance(x, str) for x in items):
                raise CmEventError(f"{where}.artefact.data_items must be a list of codes")
            if len(e["event_id"]) > 128 or len(art["id"]) > 128:
                raise CmEventError(f"{where}: ids are limited to 128 characters")
            out.append(CmEvent(e["event_id"], e["type"], art["id"], art["principal_ref"], purposes, items,
                               art.get("notice_version"), _dt(art.get("valid_until"), f"{where}.artefact.valid_until"),
                               _dt(e.get("occurred_at"), f"{where}.occurred_at"), e.get("guardian_id")))
        return out

    def report(self, payload: dict) -> None:
        if not self.cfg.report_url:
            return
        if not self.cfg.report_url.startswith("https://") and not self.cfg.report_url.startswith("http://localhost"):
            raise ValueError("report_url must use https")
        body = json.dumps({"schema": SCHEMA, "consent_manager": self.cfg.name, **payload}, sort_keys=True,
                          default=str).encode()
        ts = str(int(self._clock()))
        headers = {"Content-Type": "application/json", "X-CM-Timestamp": ts}
        secret = self._secret()
        if secret:
            headers["X-CM-Signature"] = sign_hmac(secret, ts, body)
        req = urllib.request.Request(self.cfg.report_url, data=body, headers=headers, method="POST")
        with self._open(req, timeout=5) as resp:
            if resp.status >= 300:
                raise RuntimeError(f"consent manager returned {resp.status}")


plugins.register_builtin("consent_managers", "generic", GenericConsentManager)


class ConsentManagerHub:
    def __init__(self, f, opener=None):
        self.f, self._opener = f, opener
        self.cfgs = {c.name: c for c in f.config.consent_managers}
        purposes = {p.id for p in f.config.purposes}
        for c in self.cfgs.values():
            if ":" in c.name:
                raise ValueError(f"consent manager name '{c.name}' must not contain ':'")
            bad = sorted(v for v in c.purpose_map.values() if v not in purposes)
            if bad:
                raise ValueError(f"consent manager '{c.name}': purpose_map points at unknown purposes {bad}")
        self._adapters: dict[str, Any] = {}

    def names(self) -> list[str]:
        return sorted(self.cfgs)

    def adapter(self, name: str):
        if name not in self.cfgs:
            raise KeyError(f"unknown consent manager '{name}'")
        if name not in self._adapters:
            factory = plugins.get("consent_managers", self.cfgs[name].type)
            self._adapters[name] = factory(self.cfgs[name], opener=self._opener)
        return self._adapters[name]

    def describe(self) -> list[dict]:
        return [{"name": c.name, "type": c.type, "registration_ref": c.registration_ref,
                 "verification": c.verification.mode, "purposes": dict(c.purpose_map),
                 "erase_on_withdrawal": c.erase_on_withdrawal, "erase_on_expiry": c.erase_on_expiry,
                 "reports_withdrawals": bool(c.report_url)} for c in self.cfgs.values()]

    # ---- inbound -------------------------------------------------------------
    def receive(self, name: str, headers: dict[str, str], body: bytes) -> dict:
        ad = self.adapter(name)
        ad.verify(headers, body)
        results = [self.apply(name, e) for e in ad.parse(body)]
        counts: dict[str, int] = {}
        for r in results:
            counts[r["outcome"]] = counts.get(r["outcome"], 0) + 1
        self.f.notifications.emit("consent_manager_event", {"consent_manager": name, "outcomes": counts})
        return {"consent_manager": name, "results": results}

    def apply(self, name: str, e: CmEvent) -> dict:
        cfg = self.cfgs[name]
        key = hashlib.sha256(f"{name}\x00{e.event_id}".encode()).hexdigest()
        claim = self.f.store.claim_cm_event(key, name, e.event_id, max(600, 2 * cfg.verification.replay_window_seconds))
        if claim != "claimed":
            return {"event_id": e.event_id, "type": e.type, "outcome": claim}
        try:
            outcome, detail = self._apply(cfg, e)
        except Exception:
            self.f.store.release_cm_event(key)
            raise
        self.f.store.finish_cm_event(key, outcome, json.dumps(detail, default=str))
        return {"event_id": e.event_id, "type": e.type, "outcome": outcome, **detail}

    def _apply(self, cfg, e: CmEvent) -> tuple[str, dict]:
        name, source = cfg.name, f"consent_manager:{cfg.name}"
        ref = f"{name}:{e.artefact_id}"
        create = e.type == "given" and cfg.create_principals
        pid = self.f.vault.resolve_principal(e.principal_ref, cfg.id_type, create=create)
        if not pid:
            return "refused", {"reason": "unknown principal reference"}
        self.f.store.ensure_principal(pid)
        extra = {"cm_event_id": e.event_id, "artefact_id": e.artefact_id, "registration_ref": cfg.registration_ref,
                 "occurred_at": e.occurred_at.isoformat() if e.occurred_at else None}

        def refuse(reason: str) -> tuple[str, dict]:
            self.f.ledger._record(pid, "consent_manager_event_refused", source, source, None, reason=reason,
                                  event_type=e.type, **extra)
            return "refused", {"principal_id": pid, "reason": reason}

        unknown = [p for p in e.purposes if p not in cfg.purpose_map]
        if unknown:
            return refuse(f"purposes not mapped for this consent manager: {unknown}")
        purposes = sorted({cfg.purpose_map[p] for p in e.purposes})
        if e.type == "given":
            items = [x for x in e.data_items if x not in cfg.element_map]
            if items:
                return refuse(f"data items not mapped for this consent manager: {items}")
            elements = sorted({cfg.element_map[x] for x in e.data_items}) or None
            art = self.f.store.get_artefact(ref)
            if art is not None and art["status"] != "active":
                return refuse(f"artefact is already {art['status']}")
            if e.valid_until is not None and e.valid_until <= utcnow():
                return refuse("artefact has already expired")
            try:
                for p in purposes:        # check every purpose first, so nothing is half-applied
                    if self.f.ledger.children is not None:
                        self.f.ledger.children.check_grant(pid, p, e.guardian_id)
            except (ConsentDenied, ValueError) as exc:
                return refuse(str(exc))
            ids = []
            for p in purposes:
                ids += self.f.ledger.grant(pid, p, elements, e.notice_version or "v1", consent_manager_ref=ref,
                                           source=source, actor=source, guardian_id=e.guardian_id,
                                           verification_ref=e.event_id, extra=extra)
            self.f.store.put_artefact({"ref": ref, "consent_manager": name, "artefact_id": e.artefact_id,
                                       "principal_id": pid, "purposes": purposes, "status": "active",
                                       "valid_until": e.valid_until, "updated_at": utcnow()})
            return "applied", {"principal_id": pid, "purposes": purposes, "consent_ids": ids}
        if e.type == "denied":
            for p in purposes:
                self.f.ledger.deny(pid, p, source=source, actor=source, notice_version=e.notice_version,
                                   consent_manager_ref=ref, verification_ref=e.event_id, extra=extra)
            return "recorded", {"principal_id": pid, "purposes": purposes}
        return self._end(cfg, pid, ref, e.type, e.event_id, purposes, extra)

    def _end(self, cfg, pid: str, ref: str, kind: str, event_id: str, purposes: list[str], extra: dict):
        source = f"consent_manager:{cfg.name}"
        art = self.f.store.get_artefact(ref)
        if art is not None:
            self.f.store.put_artefact({**art, "status": kind, "updated_at": utcnow()})
        rows = self.f.ledger.withdraw_rows(pid, None, consent_manager_ref=ref, source=source, actor=source, kind=kind,
                                           verification_ref=event_id, extra=extra)
        affected = sorted({r["purpose_id"] for r in rows} | set(purposes) | set((art or {}).get("purposes") or []))
        erase = cfg.erase_on_withdrawal if kind == "withdrawn" else cfg.erase_on_expiry
        erasures, still_held = [], []
        for p in affected:
            if self.f.ledger.has_effective(pid, p):
                still_held.append(p)          # consent for the purpose remains through another channel
                continue
            if erase and self.f.store.get_purpose(p) is not None:
                res = self.f.submit_request(pid, withdraw_purpose=p, requested_by=source, verified_by=source,
                                            verification_ref=event_id, requested_via="consent_manager",
                                            idempotency_key=f"{event_id}:{p}")
                erasures.append({"purpose": p, "request_id": res["request_id"]})
        return "applied", {"principal_id": pid, "withdrawn": len(rows), "erasures": erasures, "still_held": still_held}

    def expire_due(self) -> list[dict]:
        """Treat artefacts past ``valid_until`` as expired (schedule daily, like ``purge-escrows``)."""
        from sqlalchemy import select

        from ..lineage.store import consent_artefact

        now, out = utcnow(), []
        with self.f.store.engine.connect() as c:
            rows = [dict(r._mapping) for r in c.execute(select(consent_artefact).where(
                consent_artefact.c.status == "active", consent_artefact.c.valid_until.is_not(None)))]
        for a in rows:
            vu = a["valid_until"] if a["valid_until"].tzinfo else a["valid_until"].replace(tzinfo=timezone.utc)
            if vu > now or a["consent_manager"] not in self.cfgs:
                continue
            cfg = self.cfgs[a["consent_manager"]]
            eid = f"local-expiry:{a['artefact_id']}"
            key = hashlib.sha256(f"{cfg.name}\x00{eid}".encode()).hexdigest()
            if self.f.store.claim_cm_event(key, cfg.name, eid, 600) != "claimed":
                continue
            outcome, detail = self._end(cfg, a["principal_id"], a["ref"], "expired", eid, [],
                                        {"artefact_id": a["artefact_id"], "valid_until": vu.isoformat()})
            self.f.store.finish_cm_event(key, outcome, json.dumps(detail, default=str))
            out.append({"ref": a["ref"], "outcome": outcome, **detail})
        return out

    # ---- outbound ---------------------------------------------------------------
    def report_withdrawal(self, principal_id: str, rows: list[dict], source: str, actor: str) -> None:
        """Tell each Consent Manager whose consents were withdrawn here (not through it). Never raises."""
        by_ref: dict[str, list[dict]] = {}
        for r in rows:
            ref = r.get("consent_manager_ref") or ""
            cm = ref.split(":", 1)[0] if ":" in ref else None
            if cm in self.cfgs and source != f"consent_manager:{cm}":
                by_ref.setdefault(ref, []).append(r)
        for ref, rs in by_ref.items():
            cm, artefact_id = ref.split(":", 1)
            purposes = sorted({r["purpose_id"] for r in rs})
            payload = {"events": [{"type": "withdrawn", "artefact_id": artefact_id, "purposes": purposes,
                                   "occurred_at": utcnow().isoformat(), "withdrawn_via": "data_fiduciary"}]}
            ok, error = True, None
            try:
                ad = self.adapter(cm)
                if hasattr(ad, "report"):
                    ad.report(payload)
            except Exception as exc:  # noqa: BLE001 - reporting must never stop a withdrawal
                ok, error = False, f"{type(exc).__name__}: {exc}"[:300]
                log.warning("could not report withdrawal to consent manager %s: %s", cm, error)
            self.f.ledger._record(principal_id, "reported_to_consent_manager", source, actor, None,
                                  consent_manager=cm, artefact_id=artefact_id, purposes=purposes, ok=ok, error=error,
                                  sent=bool(self.cfgs[cm].report_url))
