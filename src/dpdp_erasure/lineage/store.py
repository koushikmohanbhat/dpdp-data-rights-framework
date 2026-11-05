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
        with self.engine.begin() as c:
            c.execute(purpose.delete().where(purpose.c.purpose_id == p.purpose_id))
            c.execute(purpose.insert().values(purpose_id=p.purpose_id, description=p.description,
                                              legal_basis=p.legal_basis, retention_days=p.retention_days,
                                              legal_hold_basis=p.legal_hold_basis))

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
        q = update(consent).where(consent.c.principal_id == principal_id, consent.c.purpose_id == purpose_id,
                                  consent.c.status == "granted")
        if element_type:
            q = q.where(consent.c.element_type == element_type)
        with self.engine.begin() as c:
            return c.execute(q.values(status="withdrawn", withdrawn_at=utcnow())).rowcount

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
        with self.engine.begin() as c:
            for eid in set(element_ids):
                if not c.execute(select(artifact_element).where(artifact_element.c.artifact_id == artifact_id,
                                                                artifact_element.c.element_id == eid)).first():
                    c.execute(artifact_element.insert().values(artifact_id=artifact_id, element_id=eid))

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
        with self.engine.connect() as c:
            rows = c.execute(select(artifact).select_from(j).where(data_element.c.principal_id == principal_id)
                             .distinct()).all()
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
    def add_request(self, r: ErasureRequest) -> None:
        with self.engine.begin() as c:
            c.execute(erasure_request.insert().values(
                request_id=r.request_id, principal_id=r.principal_id, scope=r.scope,
                requested_via=r.requested_via, status=r.status, dry_run=r.dry_run,
                received_at=r.received_at, due_by=r.due_by))

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

    def add_certificate(self, request_id: str, payload: str, sha: str, prev: str | None) -> None:
        with self.engine.begin() as c:
            c.execute(erasure_certificate.insert().values(request_id=request_id, payload=payload, sha256=sha,
                                                          prev_sha256=prev, issued_at=utcnow()))

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

    def stats(self) -> dict[str, int]:
        with self.engine.connect() as c:
            return {t.name: c.execute(select(func.count()).select_from(t)).scalar_one()
                    for t in (data_principal, data_element, artifact, lineage_edge, erasure_request)}
