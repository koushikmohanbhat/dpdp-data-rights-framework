"""Consent ledger at (principal x element type x purpose) granularity."""
from __future__ import annotations

from dataclasses import dataclass

from ..core.models import ConsentRecord, new_id
from ..lineage.store import LineageStore


class ConsentDenied(PermissionError):
    pass


@dataclass
class ConsentDecision:
    allowed: bool
    purpose_id: str
    missing_element_types: list[str]
    basis: str


class ConsentLedger:
    def __init__(self, store: LineageStore):
        self.store = store

    def grant(self, principal_id: str, purpose_id: str, element_types: list[str] | None = None,
              notice_version: str = "v1", consent_manager_ref: str | None = None) -> list[str]:
        self.store.ensure_principal(principal_id)
        ids = []
        for et in element_types or ["*"]:
            rec = ConsentRecord(new_id("cns"), principal_id, purpose_id, et, notice_version,
                                consent_manager_ref=consent_manager_ref)
            self.store.add_consent(rec)
            ids.append(rec.consent_id)
        return ids

    def withdraw(self, principal_id: str, purpose_id: str, element_type: str | None = None) -> int:
        return self.store.withdraw_consent(principal_id, purpose_id, element_type)

    def check(self, principal_id: str, purpose_id: str, element_types: set[str]) -> ConsentDecision:
        p = self.store.get_purpose(purpose_id)
        if p is None:
            return ConsentDecision(False, purpose_id, sorted(element_types), "unknown_purpose")
        if p.legal_basis == "legitimate_use":
            return ConsentDecision(True, purpose_id, [], "legitimate_use")
        granted = set(self.store.active_consents(principal_id, purpose_id))
        if "*" in granted:
            return ConsentDecision(True, purpose_id, [], "consent")
        missing = sorted(t for t in element_types | {"FREE_TEXT"} if t not in granted)
        return ConsentDecision(not missing, purpose_id, missing, "consent")
