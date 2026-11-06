"""Control-plane store: principals, elements, purposes, consent, artifacts,
lineage edges, erasure requests/actions/certificates.

Uses SQLAlchemy Core so the same code runs on SQLite (dev), Aurora/RDS
PostgreSQL, Cloud SQL or AlloyDB. See docs/lineage-data-model.md.
"""
from __future__ import annotations

import json
from collections import deque
from pathlib import Path
from typing import Any, Iterable

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    UniqueConstraint,
    create_engine,
    func,
    select,
    update,
)

from ..core.models import (
    ActionResult,
    Artifact,
    ConsentRecord,
    DataElement,
    DataPrincipal,
    ErasureRequest,
    PrincipalStatus,
    Purpose,
    new_id,
    utcnow,
)

md = MetaData()

data_principal = Table(
    "data_principal", md,
    Column("principal_id", String(64), primary_key=True),
    Column("status", String(24), nullable=False, default="active"),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("erased_at", DateTime(timezone=True)),
)
data_element = Table(
    "data_element", md,
    Column("element_id", String(64), primary_key=True),
    Column("principal_id", String(64), ForeignKey("data_principal.principal_id"), index=True, nullable=False),
    Column("element_type", String(40), nullable=False),
    Column("token", String(64), index=True),
    Column("third_party", Boolean, default=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
)
purpose = Table(
    "purpose", md,
    Column("purpose_id", String(64), primary_key=True),
    Column("description", Text),
    Column("legal_basis", String(24), default="consent"),
    Column("retention_days", Integer),
    Column("legal_hold_basis", Text),
)
consent = Table(
    "consent", md,
    Column("consent_id", String(64), primary_key=True),
    Column("principal_id", String(64), ForeignKey("data_principal.principal_id"), index=True, nullable=False),
    Column("purpose_id", String(64), ForeignKey("purpose.purpose_id"), nullable=False),
    Column("element_type", String(40), nullable=False, default="*"),
    Column("notice_version", String(24)),
    Column("status", String(16), nullable=False, default="granted"),
    Column("consent_manager_ref", String(128)),
    Column("granted_at", DateTime(timezone=True), nullable=False),
    Column("withdrawn_at", DateTime(timezone=True)),
)
artifact = Table(
    "artifact", md,
    Column("artifact_id", String(64), primary_key=True),
    Column("kind", String(32), index=True, nullable=False),
    Column("store", String(64), index=True, nullable=False),
    Column("locator", JSON, nullable=False),
    Column("purpose_id", String(64)),
    Column("status", String(24), nullable=False, default="live"),
    Column("contains_raw_pii", Boolean, default=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("retain_until", DateTime(timezone=True)),
)
artifact_element = Table(
    "artifact_element", md,
    Column("artifact_id", String(64), ForeignKey("artifact.artifact_id"), primary_key=True),
    Column("element_id", String(64), ForeignKey("data_element.element_id"), primary_key=True),
)
lineage_edge = Table(
    "lineage_edge", md,
    Column("parent_artifact_id", String(64), ForeignKey("artifact.artifact_id"), primary_key=True),
    Column("child_artifact_id", String(64), ForeignKey("artifact.artifact_id"), primary_key=True, index=True),
    Column("edge_type", String(16), nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
)
erasure_request = Table(
    "erasure_request", md,
    Column("request_id", String(64), primary_key=True),
    Column("principal_id", String(64), index=True, nullable=False),
    Column("scope", String(64), nullable=False, default="full"),
    Column("requested_via", String(32)),
    Column("status", String(32), nullable=False),
    Column("dry_run", Boolean, default=False),
    Column("received_at", DateTime(timezone=True), nullable=False),
    Column("due_by", DateTime(timezone=True)),
    Column("completed_at", DateTime(timezone=True)),
    Column("idempotency_key", String(128), unique=True),
    Column("requested_by", String(128)),                 # authenticated caller (role:name)
    Column("verified_by", String(128)),                  # who verified the requester upstream (system/person)
    Column("verification_ref", String(256)),             # upstream reference: case id, KYC check id, session id
)
erasure_action = Table(
    "erasure_action", md,
    Column("action_id", String(64), primary_key=True),
    Column("request_id", String(64), ForeignKey("erasure_request.request_id"), index=True, nullable=False),
    Column("artifact_id", String(64)),
    Column("store", String(64)),
    Column("action", String(24), nullable=False),
    Column("ok", Boolean, nullable=False),
    Column("detail", JSON),
    Column("executed_at", DateTime(timezone=True), nullable=False),
)
erasure_certificate = Table(
    "erasure_certificate", md,
    Column("seq", Integer, primary_key=True, autoincrement=True),
    Column("request_id", String(64), index=True, nullable=False),
    Column("payload", Text, nullable=False),
    Column("sha256", String(64), nullable=False),
    Column("prev_sha256", String(64)),
    Column("issued_at", DateTime(timezone=True), nullable=False),
    Column("signature", Text),                            # base64; over sha256 of payload
    Column("signer", String(256)),                        # key id used to sign
    Column("archive_uri", Text),                          # immutable copy (S3 Object Lock / GCS lock / local)
)

job = Table(
    "job", md,
    Column("job_id", String(64), primary_key=True),
    Column("kind", String(32), nullable=False),
    Column("payload", JSON, nullable=False),
    Column("status", String(16), nullable=False, index=True),     # queued | running | done | failed
    Column("attempts", Integer, nullable=False, default=0),
    Column("max_attempts", Integer, nullable=False, default=5),
    Column("run_after", DateTime(timezone=True), nullable=False),
    Column("locked_by", String(128)),
    Column("locked_until", DateTime(timezone=True)),
    Column("idempotency_key", String(128), unique=True),
    Column("last_error", Text),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
)

access_grant = Table(
    "access_grant", md,
    Column("grant_id", String(64), primary_key=True),
    Column("sealed_id", String(80), nullable=False),          # hold_<pid> / escrow_<pid>
    Column("requested_by", String(128), nullable=False),
    Column("approved_by", String(128)),
    Column("reason", Text, nullable=False),
    Column("ticket_ref", String(128), nullable=False),
    Column("status", String(16), nullable=False),             # pending | active | revoked | expired
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("expires_at", DateTime(timezone=True)),
)

access_log = Table(
    "access_log", md,
    Column("log_id", String(64), primary_key=True),
    Column("grant_id", String(64), index=True),
    Column("actor", String(128), nullable=False),
    Column("token", String(64)),
    Column("outcome", String(16), nullable=False),            # allowed | denied
    Column("detail", Text),
    Column("at", DateTime(timezone=True), nullable=False),
)


retention_escrow = Table(
    "retention_escrow", md,
    Column("escrow_id", String(80), primary_key=True),
    Column("principal_id", String(64), index=True, nullable=False),
    Column("request_id", String(64)),
    Column("basis", Text),
    Column("purge_after", DateTime(timezone=True), index=True, nullable=False),
    Column("status", String(16), nullable=False, default="sealed"),   # sealed | purged
    Column("purged_at", DateTime(timezone=True)),
)

# Append-only, hash-chained case log per request: manual actions and reviewer sign-offs.
case_event = Table(
    "case_event", md,
    Column("seq", Integer, primary_key=True, autoincrement=True),
    Column("event_id", String(64), unique=True, nullable=False),
    Column("request_id", String(64), ForeignKey("erasure_request.request_id"), index=True, nullable=False),
    Column("kind", String(24), nullable=False),               # manual_action | review
    Column("actor", String(128), nullable=False),
    Column("body", Text, nullable=False),                     # canonical JSON
    Column("at", DateTime(timezone=True), nullable=False),
    Column("prev_sha256", String(64), nullable=False),        # previous event, or the certificate / request anchor
    Column("sha256", String(64), nullable=False),
    Column("signature", Text),
    Column("signer", String(256)),
)

# Rights workflow (docs/rights.md). Free text and values are stored as vault tokens of the principal.
rights_case = Table(
    "rights_case", md,
    Column("case_id", String(64), primary_key=True),
    Column("type", String(24), index=True, nullable=False),     # access | correction | nomination | ...
    Column("principal_id", String(64), index=True, nullable=False),
    Column("status", String(24), index=True, nullable=False),   # received | in_review | fulfilled | rejected | ...
    Column("channel", String(64)),
    Column("requested_by", String(128)),
    Column("verified_by", String(128)),
    Column("verification_ref", String(256)),
    Column("on_behalf_of", String(64)),                         # nomination id when a nominee acts
    Column("received_at", DateTime(timezone=True), nullable=False),
    Column("due_by", DateTime(timezone=True), nullable=False),
    Column("closed_at", DateTime(timezone=True)),
    Column("rule_set", String(64), nullable=False),
    Column("rule_version", String(32), nullable=False),
    Column("rule_sha256", String(64), nullable=False),
    Column("erasure_request_id", String(64)),
    Column("details", JSON),
    Column("outcome", JSON),
    Column("idempotency_key", String(128), unique=True),
)
rights_event = Table(
    "rights_event", md,
    Column("seq", Integer, primary_key=True, autoincrement=True),
    Column("event_id", String(64), unique=True, nullable=False),
    Column("case_id", String(64), ForeignKey("rights_case.case_id"), index=True, nullable=False),
    Column("kind", String(32), nullable=False),
    Column("actor", String(128), nullable=False),
    Column("body", Text, nullable=False),
    Column("at", DateTime(timezone=True), nullable=False),
    Column("prev_sha256", String(64), nullable=False),
    Column("sha256", String(64), nullable=False),
    Column("signature", Text),
    Column("signer", String(256)),
)
breach_assessment = Table(
    # One row per assessment of a personal data breach (docs/breach.md). A breach can be re-assessed as facts
    # emerge; each assessment is kept, signed, with the report hash. The report holds pseudonymous ids only.
    "breach_assessment", md,
    Column("assessment_id", String(64), primary_key=True),
    Column("breach_id", String(64), index=True, nullable=False),
    Column("assessed_at", DateTime(timezone=True), nullable=False),
    Column("assessed_by", String(128), nullable=False),
    Column("aware_at", DateTime(timezone=True), nullable=False),
    Column("window_start", DateTime(timezone=True)),
    Column("window_end", DateTime(timezone=True), nullable=False),
    Column("stores", JSON, nullable=False),
    Column("rule_set", String(64), nullable=False),
    Column("rule_version", String(32), nullable=False),
    Column("rule_sha256", String(64), nullable=False),
    Column("report", JSON, nullable=False),
    Column("report_sha256", String(64), nullable=False),
    Column("signature", Text),
    Column("signer", String(256)),
)
nomination = Table(
    "nomination", md,
    Column("nomination_id", String(64), primary_key=True),
    Column("principal_id", String(64), index=True, nullable=False),
    Column("nominee_name", String(64)),                        # vault token
    Column("nominee_contact", String(64)),                     # vault token
    Column("relationship", String(64)),
    Column("events", String(24), nullable=False),               # death | incapacity | both
    Column("status", String(16), nullable=False),               # active | invoked | revoked
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("revoked_at", DateTime(timezone=True)),
    Column("invoked_at", DateTime(timezone=True)),
    Column("invocation_case_id", String(64)),
)


# ---- consent evidence, Consent Managers, children (docs/consent-managers.md, docs/children.md) ----------------
consent_event = Table(
    # Append-only, hash-chained and signed history of consent per principal: given, denied, withdrawn, expired,
    # and guardian verifications. The Data Fiduciary must be able to prove notice and consent (Act s.6(10)).
    # Bodies hold pseudonymous ids and references only. The unique constraint on (principal, prev) makes two
    # concurrent appends fork-proof: the loser re-reads the head and retries.
    "consent_event", md,
    Column("seq", Integer, primary_key=True, autoincrement=True),
    Column("event_id", String(64), unique=True, nullable=False),
    Column("principal_id", String(64), index=True, nullable=False),
    Column("kind", String(32), nullable=False),
    Column("purpose_id", String(64)),
    Column("source", String(96), nullable=False),          # direct | consent_manager:<name> | children | rights
    Column("actor", String(128), nullable=False),
    Column("body", Text, nullable=False),
    Column("at", DateTime(timezone=True), nullable=False),
    Column("prev_sha256", String(64), nullable=False),
    Column("sha256", String(64), nullable=False),
    Column("signature", Text),
    Column("signer", String(256)),
    UniqueConstraint("principal_id", "prev_sha256", name="uq_consent_event_chain"),
)
consent_artefact = Table(
    # A consent artefact held by a registered Consent Manager (Act s.6(7)-(9), Rules r.4): which purposes it covers,
    # whether it is still active and until when. Consents granted from it carry consent_manager_ref "<cm>:<id>".
    "consent_artefact", md,
    Column("ref", String(160), primary_key=True),           # "<consent manager>:<artefact id>"
    Column("consent_manager", String(64), index=True, nullable=False),
    Column("artefact_id", String(128), nullable=False),
    Column("principal_id", String(64), index=True, nullable=False),
    Column("purposes", JSON, nullable=False),
    Column("status", String(16), nullable=False),           # active | withdrawn | expired
    Column("valid_until", DateTime(timezone=True)),
    Column("updated_at", DateTime(timezone=True), nullable=False),
)
cm_event_receipt = Table(
    # One row per Consent Manager event id, claimed before the event is applied, so redeliveries and concurrent
    # deliveries apply once. ``outcome`` stays null while the event is being applied.
    "cm_event_receipt", md,
    Column("receipt_key", String(64), primary_key=True),    # sha256(consent manager, event id)
    Column("consent_manager", String(64), nullable=False),
    Column("event_id", String(128), nullable=False),
    Column("received_at", DateTime(timezone=True), nullable=False),
    Column("outcome", String(32)),
    Column("detail", Text),
)
principal_age_status = Table(
    # Whether the principal is an adult, a child, or a person with disability who has a lawful guardian (Act s.9,
    # s.2(j)), how that was determined, and a reference to the check. No date of birth is stored.
    "principal_age_status", md,
    Column("principal_id", String(64), primary_key=True),
    Column("status", String(16), nullable=False),           # adult | child | ward
    Column("basis", String(64), nullable=False),            # declared | verified | fiduciary_records | ...
    Column("verification_ref", String(128)),
    Column("set_by", String(128), nullable=False),
    Column("set_at", DateTime(timezone=True), nullable=False),
)
guardian_consent = Table(
    # A verified parent or lawful guardian who can give consent for a child or ward (Rules r.10, r.11).
    "guardian_consent", md,
    Column("guardian_id", String(64), primary_key=True),
    Column("principal_id", String(64), index=True, nullable=False),      # the child or ward
    Column("guardian_principal_id", String(64), index=True, nullable=False),
    Column("relationship", String(64)),                                  # vault token
    Column("method", String(40), nullable=False),
    Column("issuer", String(64)),                                        # virtual token issuer, appointing authority
    Column("verification_ref", String(128), nullable=False),
    Column("verified_by", String(128), nullable=False),
    Column("status", String(16), nullable=False),                        # active | revoked
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("revoked_at", DateTime(timezone=True)),
    Column("revoked_reason", String(256)),
)
consent_guardian = Table(
    # Which verified guardian gave each consent row of a child or ward.
    "consent_guardian", md,
    Column("consent_id", String(64), primary_key=True),
    Column("guardian_id", String(64), index=True, nullable=False),
)

gateway_observation = Table(
    # One row per model call seen by the gateway: counts and decisions only, never values or who it was.
    "gateway_observation", md,
    Column("seq", Integer, primary_key=True, autoincrement=True),
    Column("at", DateTime(timezone=True), index=True, nullable=False),
    Column("mode", String(16), nullable=False),
    Column("route", String(16), nullable=False),
    Column("model", String(128)),
    Column("purpose_id", String(64)),
    Column("principal_known", Boolean, nullable=False),
    Column("decision", String(64), nullable=False),
    Column("would", String(64)),
    Column("strings", Integer, nullable=False),
    Column("entities", JSON, nullable=False),
)

backfill_run = Table(
    # One brownfield backfill run (docs/backfill.md): counts and the resume cursor, never content.
    "backfill_run", md,
    Column("run_id", String(64), primary_key=True),
    Column("store", String(128), nullable=False),
    Column("purpose_id", String(64), nullable=False),
    Column("status", String(16), nullable=False),         # running | completed | failed
    Column("cursor", JSON),
    Column("counts", JSON, nullable=False),
    Column("started_by", String(128), nullable=False),
    Column("started_at", DateTime(timezone=True), nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
    Column("error", Text),
)


def _art(row) -> Artifact:
    m = row._mapping
    return Artifact(
        artifact_id=m["artifact_id"], kind=m["kind"], store=m["store"],
        locator=m["locator"] if isinstance(m["locator"], dict) else json.loads(m["locator"]),
        purpose_id=m["purpose_id"], status=m["status"], contains_raw_pii=bool(m["contains_raw_pii"]),
        created_at=m["created_at"], retain_until=m["retain_until"],
    )


class LineageStore:
    def __init__(self, url: str):
        if url.startswith("sqlite:///"):
            Path(url.removeprefix("sqlite:///")).parent.mkdir(parents=True, exist_ok=True)
        self.engine = create_engine(url, future=True)
        md.create_all(self.engine)

    # ---- principals & elements ----------------------------------------
    def ensure_principal(self, principal_id: str) -> DataPrincipal:
        with self.engine.begin() as c:
            r = c.execute(select(data_principal).where(data_principal.c.principal_id == principal_id)).first()
            if r:
                m = r._mapping
                return DataPrincipal(m["principal_id"], PrincipalStatus(m["status"]), m["created_at"], m["erased_at"])
            p = DataPrincipal(principal_id)
            c.execute(data_principal.insert().values(principal_id=p.principal_id, status=p.status.value,
                                                     created_at=p.created_at))
            return p

    def get_principal(self, principal_id: str) -> DataPrincipal | None:
        with self.engine.connect() as c:
            r = c.execute(select(data_principal).where(data_principal.c.principal_id == principal_id)).first()
        if not r:
            return None
        m = r._mapping
        return DataPrincipal(m["principal_id"], PrincipalStatus(m["status"]), m["created_at"], m["erased_at"])

    def set_principal_status(self, principal_id: str, status: PrincipalStatus) -> None:
        vals: dict[str, Any] = {"status": status.value}
        if status == PrincipalStatus.ERASED:
            vals["erased_at"] = utcnow()
        with self.engine.begin() as c:
            c.execute(update(data_principal).where(data_principal.c.principal_id == principal_id).values(**vals))

    def add_element(self, el: DataElement) -> None:
        with self.engine.begin() as c:
            exists = c.execute(select(data_element.c.element_id).where(
                data_element.c.principal_id == el.principal_id, data_element.c.token == el.token)).first()
            if exists:
                el.element_id = exists[0]
                return
            c.execute(data_element.insert().values(
                element_id=el.element_id, principal_id=el.principal_id, element_type=el.element_type,
                token=el.token, third_party=el.third_party, created_at=el.created_at))

    def elements_for(self, principal_id: str) -> list[DataElement]:
        with self.engine.connect() as c:
            rows = c.execute(select(data_element).where(data_element.c.principal_id == principal_id)).all()
        return [DataElement(r.element_id, r.principal_id, r.element_type, r.token, bool(r.third_party), r.created_at)
                for r in rows]

    # ---- purposes & consent ---------------------------------------------
    def put_purpose(self, p: Purpose) -> None:
        # Upsert: consents reference purposes, so a purpose row is never deleted and re-inserted.
        vals = dict(description=p.description, legal_basis=p.legal_basis, retention_days=p.retention_days,
                    legal_hold_basis=p.legal_hold_basis)
        with self.engine.begin() as c:
            n = c.execute(update(purpose).where(purpose.c.purpose_id == p.purpose_id).values(**vals)).rowcount
            if not n:
                c.execute(purpose.insert().values(purpose_id=p.purpose_id, **vals))

    def get_purpose(self, purpose_id: str) -> Purpose | None:
        with self.engine.connect() as c:
            r = c.execute(select(purpose).where(purpose.c.purpose_id == purpose_id)).first()
        if not r:
            return None
        return Purpose(r.purpose_id, r.description or "", r.legal_basis, r.retention_days, r.legal_hold_basis)

    def add_consent(self, rec: ConsentRecord) -> None:
        with self.engine.begin() as c:
            c.execute(consent.insert().values(**rec.__dict__))

    def withdraw_consent(self, principal_id: str, purpose_id: str, element_type: str | None = None) -> int:
        return len(self.withdraw_consent_rows(principal_id, purpose_id, element_type))

    def withdraw_consent_rows(self, principal_id: str, purpose_id: str | None = None, element_type: str | None = None,
                              consent_manager_ref: str | None = None) -> list[dict]:
        """Withdraw matching granted consents; returns the rows withdrawn (as they were before)."""
        where = [consent.c.principal_id == principal_id, consent.c.status == "granted"]
        if purpose_id:
            where.append(consent.c.purpose_id == purpose_id)
        if element_type:
            where.append(consent.c.element_type == element_type)
        if consent_manager_ref:
            where.append(consent.c.consent_manager_ref == consent_manager_ref)
        with self.engine.begin() as c:
            rows = [dict(r._mapping) for r in c.execute(select(consent).where(*where))]
            if rows:
                c.execute(update(consent).where(consent.c.consent_id.in_([r["consent_id"] for r in rows]),
                                                consent.c.status == "granted")
                          .values(status="withdrawn", withdrawn_at=utcnow()))
        return rows

    def active_consent_rows(self, principal_id: str, purpose_id: str) -> list[dict]:
        with self.engine.connect() as c:
            return [dict(r._mapping) for r in c.execute(select(consent).where(
                consent.c.principal_id == principal_id, consent.c.purpose_id == purpose_id,
                consent.c.status == "granted"))]

    # ---- brownfield backfill ----------------------------------------------------------
    def put_backfill_run(self, row: dict) -> None:
        with self.engine.begin() as c:
            n = c.execute(update(backfill_run).where(backfill_run.c.run_id == row["run_id"])
                          .values(**{k: v for k, v in row.items() if k != "run_id"})).rowcount
            if not n:
                c.execute(backfill_run.insert().values(**row))

    def get_backfill_run(self, run_id: str) -> dict | None:
        with self.engine.connect() as c:
            r = c.execute(select(backfill_run).where(backfill_run.c.run_id == run_id)).first()
        return dict(r._mapping) if r else None

    def backfill_runs(self) -> list[dict]:
        with self.engine.connect() as c:
            return [dict(r._mapping) for r in c.execute(select(backfill_run).order_by(backfill_run.c.started_at))]

    # ---- model gateway ----------------------------------------------------------------
    def add_gateway_observation(self, row: dict) -> None:
        with self.engine.begin() as c:
            c.execute(gateway_observation.insert().values(**row))

    def gateway_observations(self, since=None, until=None) -> list[dict]:
        from datetime import timezone

        q = select(gateway_observation).order_by(gateway_observation.c.seq)
        naive = self.engine.dialect.name == "sqlite"
        for bound, op in ((since, "ge"), (until, "lt")):
            if bound is not None:
                b = bound.astimezone(timezone.utc)
                b = b.replace(tzinfo=None) if naive else b
                q = q.where(gateway_observation.c.at >= b if op == "ge" else gateway_observation.c.at < b)
        with self.engine.connect() as c:
            rows = [dict(r._mapping) for r in c.execute(q)]
        for r in rows:
            if r["at"].tzinfo is None:
                r["at"] = r["at"].replace(tzinfo=timezone.utc)
        return rows

    # ---- consent evidence, Consent Managers, children -----------------------------
    def add_consent_event(self, row: dict) -> None:
        with self.engine.begin() as c:
            c.execute(consent_event.insert().values(**row))

    def consent_events_for(self, principal_id: str) -> list[dict]:
        with self.engine.connect() as c:
            return [dict(r._mapping) for r in c.execute(
                select(consent_event).where(consent_event.c.principal_id == principal_id).order_by(consent_event.c.seq))]

    def last_consent_event(self, principal_id: str) -> dict | None:
        with self.engine.connect() as c:
            r = c.execute(select(consent_event).where(consent_event.c.principal_id == principal_id)
                          .order_by(consent_event.c.seq.desc()).limit(1)).first()
        return dict(r._mapping) if r else None

    def put_artefact(self, row: dict) -> None:
        with self.engine.begin() as c:
            n = c.execute(update(consent_artefact).where(consent_artefact.c.ref == row["ref"])
                          .values(**{k: v for k, v in row.items() if k != "ref"})).rowcount
            if not n:
                c.execute(consent_artefact.insert().values(**row))

    def get_artefact(self, ref: str) -> dict | None:
        with self.engine.connect() as c:
            r = c.execute(select(consent_artefact).where(consent_artefact.c.ref == ref)).first()
        return dict(r._mapping) if r else None

    def artefacts_for(self, principal_id: str) -> list[dict]:
        with self.engine.connect() as c:
            return [dict(r._mapping) for r in c.execute(
                select(consent_artefact).where(consent_artefact.c.principal_id == principal_id))]

    def claim_cm_event(self, key: str, consent_manager: str, event_id: str, stale_after_seconds: int) -> str:
        """``claimed``, ``duplicate`` (already applied) or ``in_progress`` (another delivery is applying it).
        A claim left without an outcome for longer than ``stale_after_seconds`` is taken over."""
        from datetime import timedelta

        from sqlalchemy.exc import IntegrityError

        now = utcnow()
        try:
            with self.engine.begin() as c:
                c.execute(cm_event_receipt.insert().values(receipt_key=key, consent_manager=consent_manager,
                                                           event_id=event_id, received_at=now))
            return "claimed"
        except IntegrityError:
            pass
        with self.engine.begin() as c:
            r = c.execute(select(cm_event_receipt).where(cm_event_receipt.c.receipt_key == key)).first()
            if r is None:
                return "in_progress"
            if r.outcome is not None:
                return "duplicate"
            at = r.received_at if r.received_at.tzinfo else r.received_at.replace(tzinfo=now.tzinfo)
            if now - at > timedelta(seconds=stale_after_seconds):
                n = c.execute(update(cm_event_receipt).where(cm_event_receipt.c.receipt_key == key,
                                                             cm_event_receipt.c.outcome.is_(None),
                                                             cm_event_receipt.c.received_at == r.received_at)
                              .values(received_at=now)).rowcount
                return "claimed" if n else "in_progress"
        return "in_progress"

    def finish_cm_event(self, key: str, outcome: str, detail: str | None = None) -> None:
        with self.engine.begin() as c:
            c.execute(update(cm_event_receipt).where(cm_event_receipt.c.receipt_key == key)
                      .values(outcome=outcome, detail=detail))

    def release_cm_event(self, key: str) -> None:
        """Drop a claim whose processing failed unexpectedly, so a redelivery can apply the event."""
        with self.engine.begin() as c:
            c.execute(cm_event_receipt.delete().where(cm_event_receipt.c.receipt_key == key,
                                                      cm_event_receipt.c.outcome.is_(None)))

    def set_age_status(self, row: dict) -> None:
        with self.engine.begin() as c:
            n = c.execute(update(principal_age_status).where(principal_age_status.c.principal_id == row["principal_id"])
                          .values(**{k: v for k, v in row.items() if k != "principal_id"})).rowcount
            if not n:
                c.execute(principal_age_status.insert().values(**row))

    def get_age_status(self, principal_id: str) -> dict | None:
        with self.engine.connect() as c:
            r = c.execute(select(principal_age_status).where(
                principal_age_status.c.principal_id == principal_id)).first()
        return dict(r._mapping) if r else None

    def add_guardian(self, row: dict) -> None:
        with self.engine.begin() as c:
            c.execute(guardian_consent.insert().values(**row))

    def get_guardian(self, guardian_id: str) -> dict | None:
        with self.engine.connect() as c:
            r = c.execute(select(guardian_consent).where(guardian_consent.c.guardian_id == guardian_id)).first()
        return dict(r._mapping) if r else None

    def guardians_for(self, principal_id: str) -> list[dict]:
        with self.engine.connect() as c:
            return [dict(r._mapping) for r in c.execute(select(guardian_consent).where(
                guardian_consent.c.principal_id == principal_id).order_by(guardian_consent.c.created_at))]

    def revoke_guardian(self, guardian_id: str, reason: str) -> int:
        with self.engine.begin() as c:
            return c.execute(update(guardian_consent).where(guardian_consent.c.guardian_id == guardian_id,
                                                            guardian_consent.c.status == "active")
                             .values(status="revoked", revoked_at=utcnow(), revoked_reason=reason)).rowcount

    def link_consent_guardian(self, consent_ids: Iterable[str], guardian_id: str) -> None:
        with self.engine.begin() as c:
            for cid in consent_ids:
                c.execute(consent_guardian.insert().values(consent_id=cid, guardian_id=guardian_id))

    def consent_guardians(self, consent_ids: Iterable[str]) -> dict[str, str]:
        ids = list(consent_ids)
        if not ids:
            return {}
        with self.engine.connect() as c:
            return {r.consent_id: r.guardian_id for r in c.execute(
                select(consent_guardian).where(consent_guardian.c.consent_id.in_(ids)))}

    def active_consents(self, principal_id: str, purpose_id: str) -> list[str]:
        with self.engine.connect() as c:
            rows = c.execute(select(consent.c.element_type).where(
                consent.c.principal_id == principal_id, consent.c.purpose_id == purpose_id,
                consent.c.status == "granted")).all()
        return [r[0] for r in rows]

    def consents_for(self, principal_id: str) -> list[dict]:
        with self.engine.connect() as c:
            return [dict(r._mapping) for r in c.execute(select(consent).where(consent.c.principal_id == principal_id))]

    # ---- artifacts & lineage --------------------------------------------
    def add_artifact(self, a: Artifact, element_ids: Iterable[str] = (),
                     parents: Iterable[tuple[str, str]] = ()) -> Artifact:
        with self.engine.begin() as c:
            c.execute(artifact.insert().values(
                artifact_id=a.artifact_id, kind=a.kind, store=a.store, locator=a.locator,
                purpose_id=a.purpose_id, status=a.status, contains_raw_pii=a.contains_raw_pii,
                created_at=a.created_at, retain_until=a.retain_until))
            for eid in set(element_ids):
                c.execute(artifact_element.insert().values(artifact_id=a.artifact_id, element_id=eid))
            for pid, etype in parents:
                c.execute(lineage_edge.insert().values(parent_artifact_id=pid, child_artifact_id=a.artifact_id,
                                                       edge_type=etype, created_at=utcnow()))
        return a

    def link_elements(self, artifact_id: str, element_ids: Iterable[str]) -> None:
        """Link elements to an artifact; links that already exist (or appear concurrently) are left alone."""
        from sqlalchemy.exc import IntegrityError

        for eid in set(element_ids):
            try:
                with self.engine.begin() as c:     # one row per transaction: a duplicate must not abort the rest
                    if not c.execute(select(artifact_element).where(
                            artifact_element.c.artifact_id == artifact_id,
                            artifact_element.c.element_id == eid)).first():
                        c.execute(artifact_element.insert().values(artifact_id=artifact_id, element_id=eid))
            except IntegrityError:
                continue

    def get_artifact(self, artifact_id: str) -> Artifact | None:
        with self.engine.connect() as c:
            r = c.execute(select(artifact).where(artifact.c.artifact_id == artifact_id)).first()
        return _art(r) if r else None

    def find_artifact(self, store: str, locator: dict) -> Artifact | None:
        with self.engine.connect() as c:
            for r in c.execute(select(artifact).where(artifact.c.store == store)):
                a = _art(r)
                if a.locator == locator:
                    return a
        return None

    def set_artifact_status(self, artifact_id: str, status: str) -> None:
        with self.engine.begin() as c:
            c.execute(update(artifact).where(artifact.c.artifact_id == artifact_id).values(status=status))

    def direct_artifacts(self, principal_id: str) -> list[Artifact]:
        j = artifact.join(artifact_element, artifact.c.artifact_id == artifact_element.c.artifact_id) \
                    .join(data_element, data_element.c.element_id == artifact_element.c.element_id)
        # DISTINCT on ids only: PostgreSQL has no equality operator for the JSON locator column.
        ids = select(artifact.c.artifact_id).select_from(j).where(data_element.c.principal_id == principal_id)
        with self.engine.connect() as c:
            rows = c.execute(select(artifact).where(artifact.c.artifact_id.in_(ids.scalar_subquery()))).all()
        return [_art(r) for r in rows]

    def children(self, artifact_ids: list[str]) -> list[tuple[str, str, Artifact]]:
        if not artifact_ids:
            return []
        j = lineage_edge.join(artifact, artifact.c.artifact_id == lineage_edge.c.child_artifact_id)
        with self.engine.connect() as c:
            rows = c.execute(select(lineage_edge.c.parent_artifact_id, lineage_edge.c.edge_type, artifact)
                             .select_from(j).where(lineage_edge.c.parent_artifact_id.in_(artifact_ids))).all()
        return [(r[0], r[1], _art(r)) for r in rows]

    def parents_of(self, artifact_id: str) -> list[str]:
        with self.engine.connect() as c:
            return [r[0] for r in c.execute(select(lineage_edge.c.parent_artifact_id)
                                            .where(lineage_edge.c.child_artifact_id == artifact_id))]

    def downstream(self, principal_id: str) -> list[dict]:
        """BFS over the lineage graph from every artifact that directly mentions the principal.

        Returns one entry per reachable artifact with the *weakest* edge on its
        path (aggregate > train > transform/embed > copy), the depth, and the
        direct-parent ids. Equivalent recursive-CTE SQL is in docs/lineage-data-model.md.
        """
        strength = {"copy": 0, "embed": 1, "transform": 1, "train": 2, "aggregate": 3}
        seen: dict[str, dict] = {}
        q: deque[str] = deque()
        for a in self.direct_artifacts(principal_id):
            seen[a.artifact_id] = {"artifact": a, "edge_type": None, "depth": 0, "parents": []}
            q.append(a.artifact_id)
        while q:
            frontier = list(q)
            q.clear()
            for parent_id, etype, child in self.children(frontier):
                prev = seen[parent_id]["edge_type"]
                eff = etype if prev is None or strength[etype] >= strength[prev] else prev
                if child.artifact_id in seen:
                    s = seen[child.artifact_id]
                    s["parents"].append(parent_id)
                    # Direct mentions (depth 0) stay direct; otherwise keep the weakest link.
                    if s["depth"] > 0 and strength[eff] > strength[s["edge_type"]]:
                        s["edge_type"] = eff
                    continue
                seen[child.artifact_id] = {"artifact": child, "edge_type": eff,
                                           "depth": seen[parent_id]["depth"] + 1, "parents": [parent_id]}
                q.append(child.artifact_id)
        return sorted(seen.values(), key=lambda s: s["depth"])

    def artifacts_in_stores(self, stores: Iterable[str], created_before=None) -> list[Artifact]:
        """Every artifact registered in these stores (any status), optionally created no later than a time."""
        q = select(artifact).where(artifact.c.store.in_(list(stores)))
        if created_before is not None:
            if created_before.tzinfo is not None:       # stored as UTC; SQLite compares naive text
                from datetime import timezone
                created_before = created_before.astimezone(timezone.utc)
                if self.engine.dialect.name == "sqlite":
                    created_before = created_before.replace(tzinfo=None)
            q = q.where(artifact.c.created_at <= created_before)
        with self.engine.connect() as c:
            return [_art(r) for r in c.execute(q.order_by(artifact.c.created_at)).all()]

    def elements_in_artifacts(self, artifact_ids: list[str]) -> list[tuple[str, str, str, bool]]:
        """(artifact_id, principal_id, element_type, third_party) for every element linked to these artifacts."""
        if not artifact_ids:
            return []
        j = artifact_element.join(data_element, data_element.c.element_id == artifact_element.c.element_id)
        out = []
        with self.engine.connect() as c:
            for i in range(0, len(artifact_ids), 500):          # keep IN lists small
                out += [(r[0], r[1], r[2], bool(r[3])) for r in c.execute(
                    select(artifact_element.c.artifact_id, data_element.c.principal_id, data_element.c.element_type,
                           data_element.c.third_party).select_from(j)
                    .where(artifact_element.c.artifact_id.in_(artifact_ids[i:i + 500]))).all()]
        return out

    def principals_behind(self, artifact_id: str) -> set[str]:
        """Distinct principals whose data flowed into an artifact (itself + all ancestors)."""
        ids, frontier = {artifact_id}, [artifact_id]
        with self.engine.connect() as c:
            while frontier:
                rows = c.execute(select(lineage_edge.c.parent_artifact_id)
                                 .where(lineage_edge.c.child_artifact_id.in_(frontier))).all()
                frontier = [r[0] for r in rows if r[0] not in ids]
                ids.update(frontier)
            j = artifact_element.join(data_element, data_element.c.element_id == artifact_element.c.element_id)
            rows = c.execute(select(data_element.c.principal_id).select_from(j)
                             .where(artifact_element.c.artifact_id.in_(ids)).distinct()).all()
        return {r[0] for r in rows}

    def owners_of(self, artifact_id: str) -> set[str]:
        """Principals who *own* an artifact (it was produced in their context), as opposed to
        principals merely mentioned in it. Derived artifacts inherit owners from their parents."""
        j = artifact_element.join(data_element, data_element.c.element_id == artifact_element.c.element_id)
        frontier, seen = [artifact_id], {artifact_id}
        with self.engine.connect() as c:
            while frontier:
                rows = c.execute(select(data_element.c.principal_id).select_from(j).where(
                    artifact_element.c.artifact_id.in_(frontier),
                    data_element.c.element_type.in_(["FREE_TEXT", "PRINCIPAL_REF"])).distinct()).all()
                if rows:
                    return {r[0] for r in rows}
                parents = c.execute(select(lineage_edge.c.parent_artifact_id)
                                    .where(lineage_edge.c.child_artifact_id.in_(frontier))).all()
                frontier = [r[0] for r in parents if r[0] not in seen]
                seen.update(frontier)
        return set()

    def tokens_in_artifact_for(self, artifact_id: str, principal_id: str) -> list[str]:
        j = artifact_element.join(data_element, data_element.c.element_id == artifact_element.c.element_id)
        with self.engine.connect() as c:
            rows = c.execute(select(data_element.c.token).select_from(j).where(
                artifact_element.c.artifact_id == artifact_id, data_element.c.principal_id == principal_id)).all()
        return [r[0] for r in rows if r[0]]

    # ---- erasure bookkeeping --------------------------------------------
    def add_request(self, r: ErasureRequest, idempotency_key: str | None = None,
                    requested_by: str | None = None, verified_by: str | None = None,
                    verification_ref: str | None = None) -> None:
        # Verification fields go in the same insert, so a concurrent retry never sees a half-written request.
        with self.engine.begin() as c:
            c.execute(erasure_request.insert().values(
                request_id=r.request_id, principal_id=r.principal_id, scope=r.scope,
                requested_via=r.requested_via, status=r.status, dry_run=r.dry_run,
                received_at=r.received_at, due_by=r.due_by, idempotency_key=idempotency_key,
                requested_by=requested_by, verified_by=verified_by, verification_ref=verification_ref))

    def request_by_idempotency_key(self, key: str) -> dict | None:
        with self.engine.connect() as c:
            r = c.execute(select(erasure_request).where(erasure_request.c.idempotency_key == key)).first()
        return dict(r._mapping) if r else None

    def record_verification(self, request_id: str, verified_by: str | None, verification_ref: str | None) -> None:
        with self.engine.begin() as c:
            c.execute(update(erasure_request).where(erasure_request.c.request_id == request_id).values(
                verified_by=verified_by, verification_ref=verification_ref))

    def open_requests(self) -> list[dict]:
        done = ("completed", "completed_with_exceptions", "failed", "planned", "rejected")
        with self.engine.connect() as c:
            rows = c.execute(select(erasure_request).where(erasure_request.c.status.not_in(done))).all()
        return [dict(r._mapping) for r in rows]

    def set_request_status(self, request_id: str, status: str) -> None:
        vals: dict[str, Any] = {"status": status}
        if status.startswith("completed") or status == "failed":
            vals["completed_at"] = utcnow()
        with self.engine.begin() as c:
            c.execute(update(erasure_request).where(erasure_request.c.request_id == request_id).values(**vals))

    def get_request(self, request_id: str) -> dict | None:
        with self.engine.connect() as c:
            r = c.execute(select(erasure_request).where(erasure_request.c.request_id == request_id)).first()
        return dict(r._mapping) if r else None

    def add_action(self, request_id: str, res: ActionResult) -> None:
        with self.engine.begin() as c:
            c.execute(erasure_action.insert().values(
                action_id=new_id("act"), request_id=request_id, artifact_id=res.artifact_id, store=res.store,
                action=res.action, ok=res.ok, detail=res.detail, executed_at=res.executed_at))

    def actions_for(self, request_id: str) -> list[dict]:
        with self.engine.connect() as c:
            return [dict(r._mapping) for r in c.execute(
                select(erasure_action).where(erasure_action.c.request_id == request_id)
                .order_by(erasure_action.c.executed_at))]

    def last_certificate_hash(self) -> str | None:
        with self.engine.connect() as c:
            r = c.execute(select(erasure_certificate.c.sha256).order_by(erasure_certificate.c.seq.desc())).first()
        return r[0] if r else None

    def add_certificate(self, request_id: str, payload: str, sha: str, prev: str | None,
                        signature: str | None = None, signer: str | None = None,
                        archive_uri: str | None = None) -> None:
        with self.engine.begin() as c:
            c.execute(erasure_certificate.insert().values(request_id=request_id, payload=payload, sha256=sha,
                                                          prev_sha256=prev, issued_at=utcnow(), signature=signature,
                                                          signer=signer, archive_uri=archive_uri))

    def get_certificate(self, request_id: str) -> dict | None:
        with self.engine.connect() as c:
            r = c.execute(select(erasure_certificate).where(erasure_certificate.c.request_id == request_id)
                          .order_by(erasure_certificate.c.seq.desc())).first()
        return dict(r._mapping) if r else None

    def last_processed_at(self, principal_id: str):
        arts = self.direct_artifacts(principal_id)
        return max((a.created_at for a in arts), default=None)

    def add_escrow(self, escrow_id: str, principal_id: str, request_id: str, basis: str, purge_after) -> None:
        with self.engine.begin() as c:
            c.execute(retention_escrow.delete().where(retention_escrow.c.escrow_id == escrow_id))
            c.execute(retention_escrow.insert().values(escrow_id=escrow_id, principal_id=principal_id,
                                                       request_id=request_id, basis=basis,
                                                       purge_after=purge_after, status="sealed"))

    def due_escrows(self, now) -> list[dict]:
        with self.engine.connect() as c:
            rows = c.execute(select(retention_escrow).where(retention_escrow.c.status == "sealed")).all()
        out = []
        for r in rows:
            m = dict(r._mapping)
            pa = m["purge_after"]
            if pa.tzinfo is None:
                pa = pa.replace(tzinfo=now.tzinfo)
            if pa <= now:
                out.append(m)
        return out

    def mark_escrow_purged(self, escrow_id: str) -> None:
        with self.engine.begin() as c:
            c.execute(update(retention_escrow).where(retention_escrow.c.escrow_id == escrow_id)
                      .values(status="purged", purged_at=utcnow()))

    # ---- evidence ----------------------------------------------------------
    def add_case_event(self, row: dict) -> None:
        with self.engine.begin() as c:
            c.execute(case_event.insert().values(**row))

    def case_events_for(self, request_id: str) -> list[dict]:
        with self.engine.connect() as c:
            return [dict(r._mapping) for r in c.execute(
                select(case_event).where(case_event.c.request_id == request_id).order_by(case_event.c.seq))]

    def recent_requests(self, limit: int = 200, status: str | None = None,
                        principal_id: str | None = None) -> list[dict]:
        q = select(erasure_request).where(erasure_request.c.dry_run.is_(False))
        if status:
            q = q.where(erasure_request.c.status == status)
        if principal_id:
            q = q.where(erasure_request.c.principal_id == principal_id)
        with self.engine.connect() as c:
            rows = c.execute(q.order_by(erasure_request.c.received_at.desc()).limit(limit)).all()
        return [dict(r._mapping) for r in rows]

    def requests_between(self, start, end) -> list[dict]:
        """Requests received in [start, end)."""
        with self.engine.connect() as c:
            rows = c.execute(select(erasure_request).where(erasure_request.c.received_at >= start,
                                                           erasure_request.c.received_at < end)
                             .order_by(erasure_request.c.received_at)).all()
        return [dict(r._mapping) for r in rows]

    def all_certificates(self) -> list[dict]:
        with self.engine.connect() as c:
            return [dict(r._mapping) for r in c.execute(select(erasure_certificate).order_by(erasure_certificate.c.seq))]

    def escrows(self, request_id: str | None = None) -> list[dict]:
        q = select(retention_escrow)
        if request_id:
            q = q.where(retention_escrow.c.request_id == request_id)
        with self.engine.connect() as c:
            return [dict(r._mapping) for r in c.execute(q)]

    def grants(self, principal_id: str | None = None) -> list[dict]:
        q = select(access_grant).order_by(access_grant.c.created_at)
        if principal_id:
            q = q.where(access_grant.c.sealed_id == principal_id)
        with self.engine.connect() as c:
            return [dict(r._mapping) for r in c.execute(q)]

    def access_logs(self, grant_ids: list[str] | None = None) -> list[dict]:
        q = select(access_log).order_by(access_log.c.at)
        if grant_ids is not None:
            q = q.where(access_log.c.grant_id.in_(grant_ids or [""]))
        with self.engine.connect() as c:
            return [dict(r._mapping) for r in c.execute(q)]

    # ---- rights workflow ---------------------------------------------------
    def add_breach_assessment(self, row: dict) -> None:
        with self.engine.begin() as c:
            c.execute(breach_assessment.insert().values(**row))

    def breach_assessments(self, breach_id: str | None = None) -> list[dict]:
        q = select(breach_assessment).order_by(breach_assessment.c.assessed_at)
        if breach_id:
            q = q.where(breach_assessment.c.breach_id == breach_id)
        with self.engine.connect() as c:
            return [dict(r._mapping) for r in c.execute(q).all()]

    def add_rights_case(self, row: dict) -> None:
        with self.engine.begin() as c:
            c.execute(rights_case.insert().values(**row))

    def update_rights_case(self, case_id: str, **vals) -> None:
        with self.engine.begin() as c:
            c.execute(update(rights_case).where(rights_case.c.case_id == case_id).values(**vals))

    def get_rights_case(self, case_id: str) -> dict | None:
        with self.engine.connect() as c:
            r = c.execute(select(rights_case).where(rights_case.c.case_id == case_id)).first()
        return dict(r._mapping) if r else None

    def rights_case_by_key(self, key: str) -> dict | None:
        with self.engine.connect() as c:
            r = c.execute(select(rights_case).where(rights_case.c.idempotency_key == key)).first()
        return dict(r._mapping) if r else None

    def rights_cases(self, *, type: str | None = None, status: str | None = None, principal_id: str | None = None,
                     start=None, end=None) -> list[dict]:
        q = select(rights_case).order_by(rights_case.c.received_at)
        if type:
            q = q.where(rights_case.c.type == type)
        if status:
            q = q.where(rights_case.c.status == status)
        if principal_id:
            q = q.where(rights_case.c.principal_id == principal_id)
        if start is not None:
            q = q.where(rights_case.c.received_at >= start)
        if end is not None:
            q = q.where(rights_case.c.received_at < end)
        with self.engine.connect() as c:
            return [dict(r._mapping) for r in c.execute(q)]

    def add_rights_event(self, row: dict) -> None:
        with self.engine.begin() as c:
            c.execute(rights_event.insert().values(**row))

    def rights_events_for(self, case_id: str) -> list[dict]:
        with self.engine.connect() as c:
            return [dict(r._mapping) for r in c.execute(
                select(rights_event).where(rights_event.c.case_id == case_id).order_by(rights_event.c.seq))]

    def add_nomination(self, row: dict) -> None:
        with self.engine.begin() as c:
            c.execute(nomination.insert().values(**row))

    def update_nomination(self, nomination_id: str, **vals) -> None:
        with self.engine.begin() as c:
            c.execute(update(nomination).where(nomination.c.nomination_id == nomination_id).values(**vals))

    def get_nomination(self, nomination_id: str) -> dict | None:
        with self.engine.connect() as c:
            r = c.execute(select(nomination).where(nomination.c.nomination_id == nomination_id)).first()
        return dict(r._mapping) if r else None

    def nominations_for(self, principal_id: str) -> list[dict]:
        with self.engine.connect() as c:
            return [dict(r._mapping) for r in c.execute(
                select(nomination).where(nomination.c.principal_id == principal_id).order_by(nomination.c.created_at))]

    def stats(self) -> dict[str, int]:
        with self.engine.connect() as c:
            return {t.name: c.execute(select(func.count()).select_from(t)).scalar_one()
                    for t in (data_principal, data_element, artifact, lineage_edge, erasure_request)}
