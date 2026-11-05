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
from typing import Iterable, Iterator

from .connectors.base import Connector, build_connectors
from .consent.ledger import ConsentDenied, ConsentLedger
from .core import context as ctxmod
from .core.config import FrameworkConfig
from .core.context import ContextEnvelope
from .core.models import Artifact, DataElement, EdgeType, Purpose, new_id
from .erasure.orchestrator import Orchestrator
from .erasure.policy import PolicyEngine
from .lineage.store import LineageStore
from .pii.detectors import build_detector
from .pii.tokenizer import TokenizedText, Tokenizer
from .providers.base import LLMProvider, build_provider
from .vault.keys import build_key_wrapper
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

    def reveal(self, for_principal: str | None = None) -> str:
        """Detokenise for display to an authorised viewer (default: the current principal)."""
        env = ctxmod.current()
        allowed = {for_principal or (env.principal_id if env else "")}
        return self._dpdp.vault.reveal(self.text, allowed) if self._dpdp else self.text


class DataRightsFramework:
    def __init__(self, config: FrameworkConfig, provider: LLMProvider | None = None,
                 connectors: dict[str, Connector] | None = None):
        self.config = config
        self.store = LineageStore(config.lineage.url)
        self.vault = Vault(build_storage(config.vault, config.lineage.url), build_key_wrapper(config.vault))
        self.tokenizer = Tokenizer(build_detector(config.pii), self.vault)
        self.ledger = ConsentLedger(self.store)
        self.provider = provider or build_provider(config.provider)
        self.connectors = connectors if connectors is not None else build_connectors(config.connectors)
        self.orchestrator = Orchestrator(self.store, self.vault, self.connectors,
                                         PolicyEngine(config.policy), self.provider, config.policy.sla_days)
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
        if (self.config.enforce_consent if enforce_consent is None else enforce_consent):
            d = self.ledger.check(env.principal_id, env.purpose_id, types)
            if not d.allowed:
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
        for m in TOKEN_RE.finditer(content):
            tok = m.group(0)
            owner = self.vault.owner_of(tok)
            if owner:
                self.store.ensure_principal(owner)
                ids.append(self._element(owner, m.group(1), tok))
        return ids

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
        res = self.provider.generate(prot.text, system=system, **kw)
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
                else:
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

    def lineage(self, principal_id: str) -> list[dict]:
        return [{"artifact_id": e["artifact"].artifact_id, "kind": e["artifact"].kind,
                 "store": e["artifact"].store, "status": e["artifact"].status,
                 "edge": e["edge_type"] or "direct", "depth": e["depth"], "parents": e["parents"]}
                for e in self.store.downstream(principal_id)]
