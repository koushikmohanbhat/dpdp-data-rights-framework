"""Signed consent history: proof of consent the Data Fiduciary can show (Act s.6(10)).

Every change to a principal's consent is appended to one hash chain per principal: consent given, denied,
withdrawn or expired, from any source (directly, through a Consent Manager, or by a verified parent or guardian),
and the guardian verifications and status changes behind a child's consent. Each event links to the previous one
and is signed with the certificate signer when one is configured, so a later edit or deletion breaks the chain.

Bodies hold pseudonymous ids, purposes, element types, notice versions and references only, never values. A
Consent Manager keeps its own record too (Rules, First Schedule, Part B); this is the Fiduciary's side.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

from ..core.models import new_id, utcnow
from ..evidence.case import canonical, iso

KINDS = ("given", "denied", "withdrawn", "expired", "status_set", "guardian_verified", "guardian_revoked",
         "reported_to_consent_manager", "consent_manager_event_refused")


def principal_anchor(principal_id: str) -> str:
    return hashlib.sha256(f"dpdp-rights:consent:{principal_id}".encode()).hexdigest()


def _hash(event_id: str, principal_id: str, kind: str, source: str, actor: str, body: str, prev: str) -> bytes:
    return hashlib.sha256(canonical({"event_id": event_id, "principal_id": principal_id, "kind": kind,
                                     "source": source, "actor": actor, "body": body,
                                     "prev_sha256": prev}).encode()).digest()


class ConsentHistory:
    def __init__(self, store, signer=None):
        self.store, self.signer = store, signer

    def record(self, principal_id: str, kind: str, *, source: str, actor: str, purpose_id: str | None = None,
               **body: Any) -> dict:
        if kind not in KINDS:
            raise ValueError(f"unknown consent event kind {kind}")
        from ..core.idempotency import is_unique_violation

        clean = {k: v for k, v in body.items() if v is not None}
        for _ in range(20):                    # concurrent appends: the unique (principal, prev) constraint decides
            last = self.store.last_consent_event(principal_id)
            prev = last["sha256"] if last else principal_anchor(principal_id)
            at = utcnow()
            text = canonical(clean | {"purpose_id": purpose_id, "at": at.isoformat()})
            eid = new_id("ce")
            digest = _hash(eid, principal_id, kind, source, actor, text, prev)
            sig = signer_id = None
            if self.signer is not None:
                from ..security.signing import b64

                sig, signer_id = b64(self.signer.sign(digest)), self.signer.key_id
            row = {"event_id": eid, "principal_id": principal_id, "kind": kind, "purpose_id": purpose_id,
                   "source": source, "actor": actor, "body": text, "at": at, "prev_sha256": prev,
                   "sha256": digest.hex(), "signature": sig, "signer": signer_id}
            try:
                self.store.add_consent_event(row)
            except Exception as exc:  # noqa: BLE001
                if is_unique_violation(exc):
                    continue
                raise
            return self._view(row)
        raise RuntimeError("could not append to the consent history (too much contention)")

    def events(self, principal_id: str) -> list[dict]:
        return [self._view(e) for e in self.store.consent_events_for(principal_id)]

    def verify(self, principal_id: str, public_key_pem: str | None = None) -> dict:
        """Recompute every hash and link from the principal's anchor, and check signatures."""
        from ..security.signing import unb64, verify_with_public_key

        rows = self.store.consent_events_for(principal_id)
        out = {"principal_id": principal_id, "ok": True, "events": len(rows), "broken_at": None,
               "signatures_ok": None}
        prev, sigs = principal_anchor(principal_id), []
        for e in rows:
            digest = _hash(e["event_id"], principal_id, e["kind"], e["source"], e["actor"], e["body"], e["prev_sha256"])
            if e["prev_sha256"] != prev or digest.hex() != e["sha256"]:
                out.update(ok=False, broken_at=e["event_id"])
                return out
            if e.get("signature"):
                if public_key_pem:
                    sigs.append(verify_with_public_key(public_key_pem, digest, unb64(e["signature"])))
                elif self.signer is not None:
                    sigs.append(self.signer.verify(digest, unb64(e["signature"])))
            prev = e["sha256"]
        if sigs:
            out["signatures_ok"] = all(sigs)
            out["ok"] = all(sigs)
        return out

    @staticmethod
    def _view(e: dict) -> dict:
        body = json.loads(e["body"]) if isinstance(e["body"], str) else e["body"]
        return {"event_id": e["event_id"], "kind": e["kind"], "purpose_id": e["purpose_id"], "source": e["source"],
                "actor": e["actor"], "at": iso(e["at"]), "body": body, "sha256": e["sha256"],
                "prev_sha256": e["prev_sha256"], "signed": bool(e.get("signature"))}
