"""Consent ledger at (principal x element type x purpose) granularity.

Every grant, denial and withdrawal is also appended to the principal's signed consent history (history.py).
Consents from a Consent Manager count only while their artefact is active and in date (managers.py); for a
child or a ward, only consents given by a verified parent or lawful guardian count (children.py).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..core.models import ConsentRecord, new_id, utcnow
from ..lineage.store import LineageStore


class ConsentDenied(PermissionError):
    pass


class ParentalConsentRequired(ConsentDenied):
    """A child's or ward's data needs the verifiable consent of a parent or lawful guardian (Act s.9(1))."""


class ChildProcessingRestricted(ConsentDenied):
    """Tracking, behavioural monitoring or targeted advertising directed at a child (Act s.9(3))."""


@dataclass
class ConsentDecision:
    allowed: bool
    purpose_id: str
    missing_element_types: list[str]
    basis: str


def _aware(dt):
    from datetime import timezone

    return dt if dt is None or dt.tzinfo else dt.replace(tzinfo=timezone.utc)


class ConsentLedger:
    def __init__(self, store: LineageStore, history=None, children=None):
        self.store = store
        self.history = history          # ConsentHistory, set by the framework
        self.children = children        # ChildrenDesk, set by the framework

    # ---- changes ------------------------------------------------------------
    def grant(self, principal_id: str, purpose_id: str, element_types: list[str] | None = None,
              notice_version: str = "v1", consent_manager_ref: str | None = None, *, source: str = "direct",
              actor: str = "service", guardian_id: str | None = None, verification_ref: str | None = None,
              extra: dict[str, Any] | None = None) -> list[str]:
        self.store.ensure_principal(principal_id)
        if self.children is not None:
            self.children.check_grant(principal_id, purpose_id, guardian_id)
        ids = []
        for et in element_types or ["*"]:
            rec = ConsentRecord(new_id("cns"), principal_id, purpose_id, et, notice_version,
                                consent_manager_ref=consent_manager_ref)
            self.store.add_consent(rec)
            ids.append(rec.consent_id)
        if guardian_id:
            self.store.link_consent_guardian(ids, guardian_id)
        self._record(principal_id, "given", source, actor, purpose_id, element_types=element_types or ["*"],
                     notice_version=notice_version, consent_manager_ref=consent_manager_ref, consent_ids=ids,
                     guardian_id=guardian_id, verification_ref=verification_ref, **(extra or {}))
        return ids

    def deny(self, principal_id: str, purpose_id: str, *, source: str = "direct", actor: str = "service",
             notice_version: str | None = None, consent_manager_ref: str | None = None,
             verification_ref: str | None = None, extra: dict[str, Any] | None = None) -> None:
        """Record that consent was asked for and refused (nothing is granted)."""
        self.store.ensure_principal(principal_id)
        self._record(principal_id, "denied", source, actor, purpose_id, notice_version=notice_version,
                     consent_manager_ref=consent_manager_ref, verification_ref=verification_ref, **(extra or {}))

    def withdraw(self, principal_id: str, purpose_id: str, element_type: str | None = None, **kw) -> int:
        return len(self.withdraw_rows(principal_id, purpose_id, element_type, **kw))

    def withdraw_rows(self, principal_id: str, purpose_id: str | None, element_type: str | None = None, *,
                      consent_manager_ref: str | None = None, source: str = "direct", actor: str = "service",
                      kind: str = "withdrawn", verification_ref: str | None = None,
                      extra: dict[str, Any] | None = None) -> list[dict]:
        rows = self.store.withdraw_consent_rows(principal_id, purpose_id, element_type, consent_manager_ref)
        for p in sorted({r["purpose_id"] for r in rows}):      # a withdrawal that changed nothing is not recorded
            mine = [r for r in rows if r["purpose_id"] == p]
            self._record(principal_id, kind, source, actor, p, consent_ids=[r["consent_id"] for r in mine],
                         consent_manager_ref=consent_manager_ref, element_type=element_type,
                         verification_ref=verification_ref, withdrawn=len(mine), **(extra or {}))
        return rows

    def _record(self, principal_id, kind, source, actor, purpose_id, **body) -> None:
        if self.history is not None:
            self.history.record(principal_id, kind, source=source, actor=actor, purpose_id=purpose_id, **body)

    # ---- decisions ------------------------------------------------------------
    def effective_rows(self, principal_id: str, purpose_id: str) -> list[dict]:
        """Granted consents that still count: Consent Manager artefacts active and in date."""
        now, out, seen = utcnow(), [], {}
        for r in self.store.active_consent_rows(principal_id, purpose_id):
            ref = r.get("consent_manager_ref")
            if ref and ":" in ref:
                if ref not in seen:
                    seen[ref] = self.store.get_artefact(ref)
                art = seen[ref]
                if art is not None:
                    vu = _aware(art["valid_until"])
                    if art["status"] != "active" or (vu is not None and vu <= now):
                        continue
            out.append(r)
        return out

    def has_effective(self, principal_id: str, purpose_id: str) -> bool:
        return bool(self.effective_rows(principal_id, purpose_id))

    def check(self, principal_id: str, purpose_id: str, element_types: set[str]) -> ConsentDecision:
        p = self.store.get_purpose(purpose_id)
        if p is None:
            return ConsentDecision(False, purpose_id, sorted(element_types), "unknown_purpose")
        rows = None
        ch = self.children
        if ch is not None and ch.enabled:
            status = ch.status_of(principal_id)
            if status in ("child", "ward"):
                exemption = ch.exemption(purpose_id)
                if exemption:
                    return ConsentDecision(True, purpose_id, [], f"child_exemption:{exemption}")
                if ch.restricted(purpose_id):
                    return ConsentDecision(False, purpose_id, sorted(element_types), "child_restricted_s9_3")
                if p.legal_basis == "legitimate_use":
                    return ConsentDecision(True, purpose_id, [], "legitimate_use")
                rows = ch.guardian_given(self.effective_rows(principal_id, purpose_id))
                if not rows:
                    return ConsentDecision(False, purpose_id, sorted(element_types), "parental_consent_required")
            elif status is None and ch.unknown_status == "deny" and p.legal_basis != "legitimate_use" \
                    and not ch.exemption(purpose_id):
                return ConsentDecision(False, purpose_id, sorted(element_types), "age_status_unknown")
        if p.legal_basis == "legitimate_use":
            return ConsentDecision(True, purpose_id, [], "legitimate_use")
        if rows is None:
            rows = self.effective_rows(principal_id, purpose_id)
        granted = {r["element_type"] for r in rows}
        if "*" in granted:
            return ConsentDecision(True, purpose_id, [], "consent")
        missing = sorted(t for t in element_types | {"FREE_TEXT"} if t not in granted)
        return ConsentDecision(not missing, purpose_id, missing, "consent")
