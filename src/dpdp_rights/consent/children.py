"""Children and persons with disability who have a lawful guardian (Act s.9; Rules r.10-12).

Off unless ``children.enabled``. When on:

- Each principal has a status: ``adult``, ``child`` (under 18) or ``ward`` (a person with disability who has a
  lawful guardian). How it was determined (``basis``) and a reference to the check are recorded; no date of
  birth is stored. With no status, consent-based processing is refused (``unknown_status: deny``) unless the
  deployer has said the service is not offered to children (``adult``).
- A parent is recorded as a verified guardian of a child by one of the Rule 10(1) methods (records the Fiduciary
  already holds, details voluntarily provided, or a virtual token from an entrusted issuer such as a Digital
  Locker provider), with a reference to that check. A ward's guardian is recorded with the appointing authority
  (Rule 11). The guardian becomes a principal with status ``adult``.
- For a child or ward, a consent counts only if a verified guardian gave it and that guardian has not been
  revoked. Purposes marked ``child_restricted`` (tracking, behavioural monitoring, targeted advertising) are
  refused even with parental consent (s.9(3)). A purpose with a ``child_exemption`` from the rule set
  (Rule 12, Fourth Schedule) needs neither; its condition is the deployer's to keep to.

Verification itself (DigiLocker, the Fiduciary's KYC, a court order) happens upstream, like requester
verification; the framework records which method, who checked and a reference.
"""
from __future__ import annotations

from datetime import date

from ..core.models import new_id, utcnow
from ..evidence.case import iso
from .ledger import ChildProcessingRestricted, ParentalConsentRequired

STATUSES = ("adult", "child", "ward")


class ChildrenError(ValueError):
    pass


class ChildrenDesk:
    def __init__(self, f):
        from ..rights.rules import resolve

        self.f, self.store, self.cfg = f, f.store, f.config.children
        rc = f.config.rights
        rules = resolve(rc.rule_set, date.today(), None, rc.rule_sets_dir)[0].children() or {}
        self.rules = rules
        known = set((rules.get("exemptions") or {}).keys())
        self._exempt, self._restricted = {}, set()
        for p in f.config.purposes:
            if p.child_exemption:
                if p.child_exemption not in known:
                    raise ChildrenError(f"purpose '{p.id}': child_exemption '{p.child_exemption}' is not in the rule "
                                        f"set's children.exemptions ({', '.join(sorted(known)) or 'none'})")
                self._exempt[p.id] = p.child_exemption
            if p.child_restricted:
                self._restricted.add(p.id)
        for m in self.cfg.parent_methods:
            if m not in (rules.get("parent_methods") or {}):
                raise ChildrenError(f"children.parent_methods: '{m}' is not a Rule 10 method in the rule set")
        for m in self.cfg.guardian_methods:
            if m not in (rules.get("guardian_methods") or {}):
                raise ChildrenError(f"children.guardian_methods: '{m}' is not a Rule 11 authority in the rule set")

    # ---- what the ledger asks ------------------------------------------------
    @property
    def enabled(self) -> bool:
        return self.cfg.enabled

    @property
    def unknown_status(self) -> str:
        return self.cfg.unknown_status

    def status_of(self, principal_id: str) -> str | None:
        row = self.store.get_age_status(principal_id)
        return row["status"] if row else None

    def exemption(self, purpose_id: str) -> str | None:
        return self._exempt.get(purpose_id)

    def restricted(self, purpose_id: str) -> bool:
        return purpose_id in self._restricted and purpose_id not in self._exempt

    def guardian_given(self, rows: list[dict]) -> list[dict]:
        """The consent rows given by a guardian who is still active."""
        links = self.store.consent_guardians(r["consent_id"] for r in rows)
        active = {}
        out = []
        for r in rows:
            gid = links.get(r["consent_id"])
            if gid is None:
                continue
            if gid not in active:
                g = self.store.get_guardian(gid)
                active[gid] = bool(g and g["status"] == "active" and g["principal_id"] == r["principal_id"])
            if active[gid]:
                out.append(r)
        return out

    def check_grant(self, principal_id: str, purpose_id: str, guardian_id: str | None) -> None:
        """Called before consent is recorded. Raises if it would not be valid consent."""
        if guardian_id:
            g = self.store.get_guardian(guardian_id)
            if g is None or g["principal_id"] != principal_id:
                raise ChildrenError("guardian_id does not belong to this principal")
            if g["status"] != "active":
                raise ParentalConsentRequired("that guardian verification has been revoked")
        if not self.enabled:
            return
        status = self.status_of(principal_id)
        if status not in ("child", "ward"):
            if guardian_id and status == "adult":
                raise ChildrenError("guardian consent applies only to a child or a ward")
            return
        if self.exemption(purpose_id):
            return
        if self.restricted(purpose_id):
            raise ChildProcessingRestricted(
                f"purpose '{purpose_id}' involves tracking, behavioural monitoring or targeted advertising, which "
                f"Act s.9(3) does not allow for a child, even with a parent's consent")
        if not guardian_id:
            what = "a parent" if status == "child" else "the lawful guardian"
            raise ParentalConsentRequired(
                f"this principal is a {status}: consent for '{purpose_id}' must be given by {what}, verified first "
                f"(record_guardian), and passed as guardian_id")

    # ---- recording -------------------------------------------------------------
    def set_status(self, principal_id: str, status: str, *, basis: str, set_by: str,
                   verification_ref: str | None = None) -> dict:
        if status not in STATUSES:
            raise ChildrenError(f"status must be one of {', '.join(STATUSES)}")
        if not basis:
            raise ChildrenError("basis is required (how the status was determined, e.g. verified, declared)")
        self._check_refs(verification_ref=verification_ref, basis=basis)
        if self.store.get_principal(principal_id) is None:
            raise KeyError("unknown data principal")
        row = {"principal_id": principal_id, "status": status, "basis": basis, "verification_ref": verification_ref,
               "set_by": set_by, "set_at": utcnow()}
        prev = self.store.get_age_status(principal_id)
        self.store.set_age_status(row)
        self.f.ledger._record(principal_id, "status_set", "children", set_by, None, status=status, basis=basis,
                              previous=prev["status"] if prev else None, verification_ref=verification_ref)
        return self.status(principal_id)

    def record_guardian(self, principal_id: str, guardian_principal_id: str, *, method: str, verification_ref: str,
                        verified_by: str, issuer: str | None = None, relationship: str | None = None) -> dict:
        status = self.status_of(principal_id)
        if status not in ("child", "ward"):
            raise ChildrenError("set the principal's status to child or ward before recording a guardian")
        if guardian_principal_id == principal_id:
            raise ChildrenError("a principal cannot be their own guardian")
        allowed = self.cfg.parent_methods if status == "child" else self.cfg.guardian_methods
        if method not in allowed:
            rule = "Rule 10(1)" if status == "child" else "Rule 11"
            raise ChildrenError(f"method for a {status} must be one of {', '.join(allowed)} ({rule})")
        if method == "virtual_token":
            if not issuer:
                raise ChildrenError("virtual_token needs the issuer (an entity entrusted by law or the Government)")
            if self.cfg.token_issuers and issuer not in self.cfg.token_issuers:
                raise ChildrenError(f"issuer '{issuer}' is not in children.token_issuers")
        if not verification_ref:
            raise ChildrenError("verification_ref is required: a reference to the check made upstream")
        self._check_refs(verification_ref=verification_ref, verified_by=verified_by, issuer=issuer)
        if self.store.get_principal(guardian_principal_id) is None:
            raise KeyError("unknown guardian principal")
        g_status = self.status_of(guardian_principal_id)
        if g_status in ("child", "ward"):
            raise ChildrenError(f"the guardian's own status is {g_status}; a parent or guardian must be an adult")
        if g_status is None:
            # Rule 10 requires checking that the parent is an identifiable adult; this verification is that check.
            self.store.set_age_status({"principal_id": guardian_principal_id, "status": "adult",
                                             "basis": f"guardian_verification:{method}",
                                             "verification_ref": verification_ref, "set_by": verified_by,
                                             "set_at": utcnow()})
        rel = self.f.vault.tokenize(principal_id, "RIGHTS_NOTE", relationship) if relationship else None
        gid = new_id("gdn")
        self.store.add_guardian({"guardian_id": gid, "principal_id": principal_id,
                                 "guardian_principal_id": guardian_principal_id, "relationship": rel, "method": method,
                                 "issuer": issuer, "verification_ref": verification_ref, "verified_by": verified_by,
                                 "status": "active", "created_at": utcnow()})
        self.f.ledger._record(principal_id, "guardian_verified", "children", verified_by, None, guardian_id=gid,
                              guardian_principal_id=guardian_principal_id, method=method, issuer=issuer,
                              verification_ref=verification_ref, principal_status=status)
        return self._guardian_view(self.store.get_guardian(gid))

    def revoke_guardian(self, guardian_id: str, *, reason: str, actor: str) -> dict:
        g = self.store.get_guardian(guardian_id)
        if g is None:
            raise KeyError("unknown guardian")
        self._check_refs(reason=reason)
        if not self.store.revoke_guardian(guardian_id, reason):
            raise ChildrenError("guardian is already revoked")
        self.f.ledger._record(g["principal_id"], "guardian_revoked", "children", actor, None, guardian_id=guardian_id,
                              reason=reason)
        return self._guardian_view(self.store.get_guardian(guardian_id))

    # ---- views -------------------------------------------------------------------
    def status(self, principal_id: str) -> dict:
        row = self.store.get_age_status(principal_id)
        return {"principal_id": principal_id, "status": row["status"] if row else None,
                "basis": row["basis"] if row else None, "verification_ref": row["verification_ref"] if row else None,
                "set_by": row["set_by"] if row else None, "set_at": iso(row["set_at"]) if row else None,
                "enforced": self.enabled}

    def view(self, principal_id: str) -> dict:
        return self.status(principal_id) | {
            "guardians": [self._guardian_view(g) for g in self.store.guardians_for(principal_id)]}

    @staticmethod
    def _guardian_view(g: dict) -> dict:
        return {"guardian_id": g["guardian_id"], "principal_id": g["principal_id"],
                "guardian_principal_id": g["guardian_principal_id"], "relationship": g["relationship"],
                "method": g["method"], "issuer": g["issuer"], "verification_ref": g["verification_ref"],
                "verified_by": g["verified_by"], "status": g["status"], "created_at": iso(g["created_at"]),
                "revoked_at": iso(g["revoked_at"]), "revoked_reason": g["revoked_reason"]}

    def _check_refs(self, **fields: str | None) -> None:
        from ..core.idempotency import references_with_personal_data

        if not self.f.config.evidence.reject_personal_data:
            return
        bad = references_with_personal_data(self.f.tokenizer.detector, **fields)
        if bad:
            raise ChildrenError(f"{', '.join(bad)} appears to contain personal data; pass a reference "
                                "(session, ticket or case ID), not details of a person")
