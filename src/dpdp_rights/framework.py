"""DataRightsFramework: the single entry point applications use.

    dpdp = DataRightsFramework.from_yaml("dpdp.yaml")
    pid = dpdp.principal("applicant-1042")                       # pseudonymous id
    dpdp.grant_consent(pid, "policy_issuance", notice_version="2026-11")
    with dpdp.context(pid, purpose="policy_issuance", session_id="s-1"):
        safe = dpdp.protect(user_message)                       # consent check + tokenise
        row = save_application(safe.text)                       # your code
        a = dpdp.track_artifact("record", "applications", {"id": row}, content=safe.text)
        ans = dpdp.generate(safe.text, already_protected=True)
    dpdp.withdraw_consent(pid, "marketing")                     # purpose-scoped erasure
    dpdp.erase(pid)                                             # discover -> plan -> execute -> verify -> certify
"""
from __future__ import annotations

import logging
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Iterable, Iterator

from .connectors.base import Connector, build_connectors
from .consent.ledger import ConsentDenied, ConsentLedger
from .core import context as ctxmod
from .core.config import FrameworkConfig
from .core.context import ContextEnvelope
from .core.models import Artifact, DataElement, EdgeType, ErasureRequest, Purpose, RequestStatus, new_id, utcnow
from .erasure.orchestrator import Orchestrator
from .erasure.policy import PolicyEngine
from .jobs.queue import build_queue
from .lineage.store import LineageStore
from .notify import Notifications
from .observability.telemetry import Telemetry
from .pii.detectors import build_detector
from .pii.tokenizer import TokenizedText, Tokenizer
from .providers.base import LLMProvider, build_provider
from .security.breakglass import BreakGlass
from .security.guardrails import enforce as enforce_guardrails
from .security.signing import build_archive, build_signer
from .vault.keys import build_key_wrapper, build_sealed_key_wrapper
from .vault.storage import build_storage
from .vault.vault import TOKEN_RE, Vault


@dataclass
class Protected:
    text: str                       # tokenised text, safe to store / log / embed / send to a model
    element_ids: list[str]
    principals: set[str]
    tokenized: TokenizedText | None = None


@dataclass
class GuardedResponse:
    text: str                       # tokenised model output
    artifact_ids: list[str] = field(default_factory=list)  # provider-side state registered for erasure
    element_ids: list[str] = field(default_factory=list)
    _dpdp: "DataRightsFramework | None" = None

    def reveal(self, for_principal: str | None = None, masked: bool = False) -> str:
        """Detokenise for display to an authorised viewer (default: the current principal).
        ``masked=True`` shows a masked form instead (``+91 ••••• •3210``)."""
        env = ctxmod.current()
        allowed = {for_principal or (env.principal_id if env else "")}
        return self._dpdp.vault.reveal(self.text, allowed, masked=masked) if self._dpdp else self.text


class DataRightsFramework:
    def __init__(self, config: FrameworkConfig, provider: LLMProvider | None = None,
                 connectors: dict[str, Connector] | None = None):
        self.config = config
        self.warnings = enforce_guardrails(config)      # raises in production on unsafe settings
        for w in self.warnings:
            logging.getLogger("dpdp_rights").warning("production guardrail: %s", w)
        self.store = LineageStore(config.lineage.url)
        v = config.vault
        self.vault = Vault(build_storage(v, config.lineage.url), build_key_wrapper(v),
                           sealed_wrapper=build_sealed_key_wrapper(v), cache_ttl_seconds=v.cache_ttl_seconds,
                           cache_max_entries=v.cache_max_entries, surrogate_types=set(config.pii.surrogates))
        pii_llm = build_provider(config.pii.llm) if "llm" in config.pii.detectors and config.pii.llm else None
        self.tokenizer = Tokenizer(build_detector(config.pii, llm_provider=pii_llm), self.vault)
        self.ledger = ConsentLedger(self.store)
        self.provider = provider or build_provider(config.provider)
        self.connectors = connectors if connectors is not None else build_connectors(config.connectors)
        for conn in self.connectors.values():       # connectors that re-embed redacted rows use the same model
            if getattr(conn, "embedder", "absent") is None:
                conn.embedder = self.provider.embed
        self.telemetry = Telemetry(config.observability.otel)
        self.orchestrator = Orchestrator(self.store, self.vault, self.connectors,
                                         PolicyEngine(config.policy), self.provider, config.policy.sla_days,
                                         signer=build_signer(config.certificates),
                                         archive=build_archive(config.certificates), telemetry=self.telemetry)
        self.break_glass = BreakGlass(self.store, self.vault, config.break_glass)
        self.queue = build_queue(self.store, config.queue)
        self.notifications = Notifications(config.notifications)
        self.orchestrator.notifications = self.notifications
        from .evidence.case import CaseLog

        self.cases = CaseLog(self.store, self.orchestrator.signer, config.evidence, self.tokenizer.detector,
                             self.notifications)
        from .rights.desk import RightsDesk

        self.rights = RightsDesk(self)
        for p in config.purposes:
            self.store.put_purpose(Purpose(p.id, p.description, p.legal_basis, p.retention_days, p.legal_hold_basis))

    @classmethod
    def from_yaml(cls, path: str, **kw) -> "DataRightsFramework":
        return cls(FrameworkConfig.load(path), **kw)

    # ---- identity & consent -----------------------------------------------
    def principal(self, external_id: str, id_type: str = "EXTERNAL_ID") -> str:
        pid = self.vault.resolve_principal(external_id, id_type)
        self.store.ensure_principal(pid)
        return pid

    def register_identifier(self, principal_id: str, id_type: str, value: str) -> None:
        """Link an identifier (EMAIL, PHONE_IN, PAN...) to a principal so mentions anywhere resolve to them."""
        self.vault.link_identifier(principal_id, id_type, value)
        self.vault.tokenize(principal_id, id_type, value)

    def grant_consent(self, principal_id: str, purpose_id: str, element_types: list[str] | None = None, **kw):
        return self.ledger.grant(principal_id, purpose_id, element_types, **kw)

    def withdraw_consent(self, principal_id: str, purpose_id: str, erase: bool = True) -> dict:
        n = self.ledger.withdraw(principal_id, purpose_id)
        self.telemetry.withdrawals.add(n, {"purpose": purpose_id})
        out = {"withdrawn": n}
        if erase:
            out["erasure"] = self.erase(principal_id, scope=f"purpose:{purpose_id}")
        return out

    @contextmanager
    def context(self, principal_id: str, purpose: str, session_id: str | None = None,
                parents: Iterable[str] = ()) -> Iterator[ContextEnvelope]:
        env = ContextEnvelope(principal_id, purpose, session_id, tuple(parents), self.config.tenant)
        tok = ctxmod.set_current(env)
        try:
            yield env
        finally:
            ctxmod.reset(tok)

    # ---- protecting data -------------------------------------------------
    def protect(self, text: str, enforce_consent: bool | None = None) -> Protected:
        env = ctxmod.require()
        tt = self.tokenizer.tokenize(text, env.principal_id)
        types = {m.entity.type for m in tt.mentions}
        for t in types:
            self.telemetry.pii.add(sum(1 for m in tt.mentions if m.entity.type == t), {"type": t})
        if (self.config.enforce_consent if enforce_consent is None else enforce_consent):
            d = self.ledger.check(env.principal_id, env.purpose_id, types)
            if not d.allowed:
                self.telemetry.blocked.add(1, {"purpose": env.purpose_id})
                raise ConsentDenied(f"No consent for purpose '{env.purpose_id}' on {d.missing_element_types} "
                                    f"(basis={d.basis})")
        element_ids = [self._element(env.principal_id, "FREE_TEXT", None)]
        for m in tt.mentions:
            self.store.ensure_principal(m.principal_id)
            element_ids.append(self._element(m.principal_id, m.entity.type, m.token, m.third_party))
        return Protected(tt.text, element_ids, tt.principals | {env.principal_id}, tt)

    def _element(self, principal_id: str, etype: str, token: str | None, third_party: bool = False) -> str:
        if token is None:
            for el in self.store.elements_for(principal_id):
                if el.element_type == etype and el.token is None:
                    return el.element_id
        el = DataElement(new_id("el"), principal_id, etype, token, third_party)
        self.store.add_element(el)
        return el.element_id

    def elements_from_content(self, content: str) -> list[str]:
        """Link an artifact to every principal whose tokens appear in it (multi-principal summaries)."""
        ids = []
        for _, _, tok in self.vault.find_tokens(content):
            owner = self.vault.owner_of(tok)
            if owner:
                self.store.ensure_principal(owner)
                ids.append(self._element(owner, self.vault.element_type_of(tok) or "FREE_TEXT", tok))
        return ids

    def protect_document(self, data: bytes | None = None, *, filename: str | None = None,
                         s3_uri: str | None = None, enforce_consent: bool | None = None):
        """Extract a document's text (local for digital PDFs, OCR for scans and images), then detect and
        tokenise it like ``protect``. Returns the tokenised text with each detected entity's page.

        The original file still holds personal data: store it where a connector can erase it and register
        it with ``track_artifact``."""
        from .pii.documents import DocumentEntity, ProtectedDocument, build_ocr, extract_text

        if not hasattr(self, "_ocr"):
            self._ocr = build_ocr(self.config.pii.documents)
        doc = extract_text(data, filename=filename, ocr=self._ocr, s3_uri=s3_uri)
        prot = self.protect(doc.text, enforce_consent=enforce_consent)
        ents = [DocumentEntity(m.entity, doc.page_of(m.entity.start)) for m in (prot.tokenized.mentions
                                                                                 if prot.tokenized else [])]
        return ProtectedDocument(prot.text, prot.element_ids, ents, len(doc.pages), doc.source)

    # ---- lineage ----------------------------------------------------------
    def track_artifact(self, kind: str, store: str, locator: dict, *, content: str | None = None,
                       element_ids: Iterable[str] = (), parents: Iterable[str] | None = None,
                       edge_type: str | EdgeType = EdgeType.TRANSFORM, purpose: str | None = None,
                       contains_raw_pii: bool = False) -> Artifact:
        """Register a place where (tokenised) personal data now lives."""
        env = ctxmod.current()
        purpose = purpose or (env.purpose_id if env else None)
        parent_ids = list(parents) if parents is not None else list(env.parent_artifact_ids if env else [])
        els = list(element_ids)
        if content:
            els += self.elements_from_content(content)
        if env and not parent_ids:
            els.append(self._element(env.principal_id, "FREE_TEXT", None))
        a = Artifact(new_id("art"), str(kind), store, locator, purpose_id=purpose, contains_raw_pii=contains_raw_pii)
        et = edge_type.value if isinstance(edge_type, EdgeType) else edge_type
        return self.store.add_artifact(a, els, [(p, et) for p in parent_ids])

    def track_cache_key(self, redis_client, key: str, index_prefix: str = "dpdp:idx:") -> None:
        env = ctxmod.require()
        redis_client.sadd(index_prefix + env.principal_id, key)

    # ---- model calls ------------------------------------------------------
    def generate(self, prompt: str, system: str | None = None, *, provider_store: str = "openai_platform",
                 already_protected: bool = False, **kw) -> GuardedResponse:
        prot = Protected(prompt, [], set()) if already_protected else self.protect(prompt)
        with self.telemetry.span("gen_ai.generate", **{
                "gen_ai.system": getattr(self.provider, "name", "unknown"),
                "gen_ai.request.model": getattr(self.provider, "model", None)}) as sp:
            res = self.provider.generate(prot.text, system=system, **kw)
            for k_in, k_out in (("input_tokens", "gen_ai.usage.input_tokens"),
                                ("output_tokens", "gen_ai.usage.output_tokens")):
                if isinstance(res.usage.get(k_in), int):
                    sp.set_attribute(k_out, res.usage[k_in])
        arts = []
        if res.provider_ref:
            a = self.track_artifact("provider_response", provider_store, res.provider_ref,
                                    content=prot.text, element_ids=prot.element_ids, edge_type=EdgeType.COPY)
            arts.append(a.artifact_id)
        # Model may echo tokens; keep them as tokens. Any *new* raw PII it emits is tokenised too.
        env = ctxmod.require()
        out = self.tokenizer.tokenize(res.text, env.principal_id).text
        return GuardedResponse(out, arts, prot.element_ids, self)

    def embed(self, texts: list[str]) -> list[list[float]]:
        return self.provider.embed([self.protect(t).text if not TOKEN_RE.search(t) else t for t in texts])

    # ---- logging ----------------------------------------------------------
    def logging_filter(self) -> logging.Filter:
        dpdp = self

        class TokenizingFilter(logging.Filter):
            def filter(self, record: logging.LogRecord) -> bool:
                env = ctxmod.current()
                msg = record.getMessage()
                if env:
                    msg = dpdp.tokenizer.tokenize(msg, env.principal_id).text
                    record.dpdp_principal = env.principal_id
                    record.dpdp_purpose = env.purpose_id
                else:   # no principal known: mask rather than let raw PII through
                    out, cur = [], 0
                    for e in dpdp.tokenizer.detector.detect(msg):
                        out += [msg[cur:e.start], f"[{e.type}]"]
                        cur = e.end
                    msg = "".join(out) + msg[cur:]
                    record.dpdp_principal = "-"
                    record.dpdp_purpose = "-"
                record.msg, record.args = msg, ()
                return True

        return TokenizingFilter()

    # ---- erasure ------------------------------------------------------------
    def erase(self, principal_id: str, scope: str = "full", dry_run: bool = False,
              requested_via: str = "api") -> dict:
        req = self.orchestrator.submit(principal_id, scope, dry_run, requested_via)
        return self.orchestrator.run(req)

    def purge_due_escrows(self) -> list[dict]:
        return self.orchestrator.purge_due_escrows()

    # ---- durable request intake (used by the Rights API) -------------------
    def submit_request(self, principal_id: str, *, scope: str = "full", withdraw_purpose: str | None = None,
                       requested_by: str | None = None, verified_by: str | None = None,
                       verification_ref: str | None = None, requested_via: str = "api",
                       idempotency_key: str | None = None, dry_run: bool = False) -> dict:
        """Accept an erasure or withdrawal request and queue it for workers.

        Identity verification of the Data Principal happens *before* this call, in the deployer's own
        channel (login, KYC check, branch visit, contact-centre process). Pass who verified and a
        reference so the certificate and audit trail show it.
        """
        if idempotency_key:
            prev = self.store.request_by_idempotency_key(idempotency_key)
            if prev:
                return {"request_id": prev["request_id"], "status": prev["status"], "duplicate": True}
        if self.store.get_principal(principal_id) is None:
            raise KeyError("unknown data principal")
        if withdraw_purpose:
            scope = f"purpose:{withdraw_purpose}"
            requested_via = f"{requested_via}-withdrawal"
        req = ErasureRequest(new_id("er"), principal_id, scope, requested_via, dry_run=dry_run,
                             due_by=utcnow() + timedelta(days=self.config.policy.sla_days))
        self.store.add_request(req, idempotency_key, requested_by)
        self.store.record_verification(req.request_id, verified_by, verification_ref)
        job_id = self.queue.enqueue("erasure", {"request_id": req.request_id, "withdraw_purpose": withdraw_purpose},
                                    idempotency_key=f"erasure:{req.request_id}")
        return {"request_id": req.request_id, "status": req.status, "due_by": req.due_by.isoformat(),
                "job_id": job_id}

    def process_jobs(self, max_jobs: int | None = None) -> list[dict]:
        """Run queued jobs until the queue is empty (or max_jobs). Used by `dpdp-rights worker`."""
        done = []
        while max_jobs is None or len(done) < max_jobs:
            j = self.queue.claim()
            if j is None:
                break
            try:
                result = self._run_job(j)
                self.queue.complete(j["job_id"])
                done.append({"job_id": j["job_id"], "kind": j["kind"], "ok": True, "result": result})
            except Exception as e:  # noqa: BLE001
                state = self.queue.fail(j["job_id"], repr(e))
                if state == "failed" and j["kind"] == "erasure":
                    rid = j["payload"]["request_id"]
                    self.store.set_request_status(rid, RequestStatus.FAILED.value)
                    r = self.store.get_request(rid) or {}
                    self.notifications.emit("request_failed", {
                        "request_id": rid, "principal_id": r.get("principal_id"), "scope": r.get("scope"),
                        "status": "failed", "attempts": j.get("attempts"), "error_type": type(e).__name__})
                done.append({"job_id": j["job_id"], "kind": j["kind"], "ok": False, "state": state, "error": str(e)})
        return done

    def _run_job(self, j: dict):
        p = j["payload"]
        if j["kind"] == "erasure":
            r = self.store.get_request(p["request_id"])
            if p.get("withdraw_purpose"):
                self.withdraw_consent(r["principal_id"], p["withdraw_purpose"], erase=False)
            req = ErasureRequest(r["request_id"], r["principal_id"], r["scope"], r["requested_via"] or "api",
                                 status=r["status"], received_at=r["received_at"], due_by=r["due_by"],
                                 dry_run=bool(r["dry_run"]))
            res = self.orchestrator.run(req, raise_errors=True)
            return {"status": res.get("status"), "certificate_sha256": res.get("certificate_sha256")}
        if j["kind"] == "purge_escrows":
            return self.purge_due_escrows()
        raise ValueError(f"unknown job kind {j['kind']}")

    def sla_counts(self, due_soon_days: int = 7) -> dict[str, int]:
        now = utcnow()
        out = {"ok": 0, "due_soon": 0, "overdue": 0}
        for r in self.store.open_requests():
            due = r["due_by"]
            if due is None:
                continue
            due = due if due.tzinfo else due.replace(tzinfo=now.tzinfo)
            days = (due - now).total_seconds() / 86400
            out["overdue" if days < 0 else "due_soon" if days <= due_soon_days else "ok"] += 1
        return out

    def verify_certificate(self, request_id: str) -> dict:
        """Recompute the hash, check the chain link and the signature."""
        import hashlib
        import json as _json

        from .security.signing import unb64

        c = self.store.get_certificate(request_id)
        if not c:
            raise KeyError("no certificate")
        digest = hashlib.sha256(c["payload"].encode()).digest()
        body = _json.loads(c["payload"])
        out = {"request_id": request_id, "sha256": c["sha256"],
               "hash_ok": digest.hex() == c["sha256"],
               "chain_ok": body.get("prev_certificate_sha256") == c["prev_sha256"],
               "signed": bool(c["signature"]), "signer": c["signer"], "archive_uri": c["archive_uri"]}
        signer = self.orchestrator.signer
        out["signature_ok"] = (signer.verify(digest, unb64(c["signature"]))
                               if c["signature"] and signer is not None else None)
        return out

    # ---- evidence (docs/evidence.md) ---------------------------------------
    def record_manual_action(self, request_id: str, actor: str, *, system: str, action: str, reference: str,
                             notes: str | None = None, performed_at: str | None = None) -> dict:
        """Record work done outside the framework for this request (no connector, processor instructed)."""
        return self.cases.record_manual_action(request_id, actor, system=system, action=action, reference=reference,
                                               notes=notes, performed_at=performed_at)

    def review(self, request_id: str, reviewer: str, *, decision: str, checklist: dict | None = None,
               notes: str | None = None, role: str = "reviewer") -> dict:
        """Reviewer sign-off: approved | rejected | needs_info, against evidence.review_checklist."""
        return self.cases.record_review(request_id, reviewer, decision=decision, checklist=checklist, notes=notes,
                                        role=role)

    def case(self, request_id: str) -> dict:
        from .evidence.case import build_case

        return build_case(self, request_id)

    def export_evidence(self, request_id: str, path: str | None = None) -> dict:
        from .evidence.bundle import export_case_bundle

        return export_case_bundle(self, request_id, path)

    def export_audit_pack(self, start, end, path: str | None = None, inventory=None, include_cases: bool = True) -> dict:
        from .evidence.audit import export_audit_pack

        return export_audit_pack(self, start, end, path, inventory, include_cases)

    def lineage(self, principal_id: str) -> list[dict]:
        return [{"artifact_id": e["artifact"].artifact_id, "kind": e["artifact"].kind,
                 "store": e["artifact"].store, "status": e["artifact"].status,
                 "edge": e["edge_type"] or "direct", "depth": e["depth"], "parents": e["parents"]}
                for e in self.store.downstream(principal_id)]
