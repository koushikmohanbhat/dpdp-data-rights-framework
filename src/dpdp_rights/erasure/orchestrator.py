"""Erasure orchestrator: discover -> plan -> execute -> shred -> verify -> certify."""
from __future__ import annotations

import hashlib
import json
import logging
import time
from datetime import timedelta
from typing import Callable

from ..connectors.base import Connector, ErasureContext, redact_tokens
from ..core.models import (
    Action,
    ActionResult,
    Artifact,
    ArtifactStatus,
    DataElement,
    ErasureRequest,
    PlannedAction,
    PrincipalStatus,
    RequestStatus,
    new_id,
    utcnow,
)
from ..lineage.store import LineageStore
from ..providers.base import LLMProvider
from ..vault.vault import Vault
from .policy import PolicyEngine, PolicyInput

log = logging.getLogger("dpdp_rights")

Regenerator = Callable[[Artifact, ErasureContext, "Orchestrator"], str]

_PHASE = {Action.DELETE: 0, Action.REDACT: 0, Action.CRYPTO_SHRED: 0, Action.RETAIN_AGGREGATE: 1,
          Action.REGENERATE: 2, Action.FLAG_RETRAIN: 3, Action.RETAIN_LEGAL_HOLD: 3, Action.SKIP: 3}

_STATUS_AFTER = {Action.DELETE: ArtifactStatus.ERASED, Action.REDACT: ArtifactStatus.REDACTED,
                 Action.REGENERATE: ArtifactStatus.REDACTED, Action.CRYPTO_SHRED: ArtifactStatus.ERASED,
                 Action.RETAIN_AGGREGATE: ArtifactStatus.RETAINED, Action.RETAIN_LEGAL_HOLD: ArtifactStatus.RETAINED,
                 Action.FLAG_RETRAIN: ArtifactStatus.PENDING_RETRAIN}

REGEN_SYSTEM = (
    "You maintain derived summaries. Rewrite the given content so it contains no information "
    "about or attributable to the listed tokens. Remove sentences that describe them, keep everything "
    "else factual and unchanged. Never invent facts. Output only the rewritten content."
)


class Orchestrator:
    def __init__(self, store: LineageStore, vault: Vault, connectors: dict[str, Connector],
                 policy: PolicyEngine, provider: LLMProvider | None = None, sla_days: int = 30,
                 signer=None, archive=None, telemetry=None):
        from ..observability.telemetry import Telemetry

        self.store, self.vault, self.connectors, self.policy = store, vault, connectors, policy
        self.signer, self.archive = signer, archive
        self.telemetry = telemetry or Telemetry(False)
        self.retention = policy.cfg.statutory_retention
        self.provider = provider
        self.sla_days = sla_days
        self.regenerators: dict[str, Regenerator] = {}

    def register_regenerator(self, key: str, fn: Regenerator) -> None:
        """key = artifact kind or connector name."""
        self.regenerators[key] = fn

    # ------------------------------------------------------------------
    def submit(self, principal_id: str, scope: str = "full", dry_run: bool = False,
               requested_via: str = "api") -> ErasureRequest:
        req = ErasureRequest(new_id("er"), principal_id, scope, requested_via, dry_run=dry_run,
                             due_by=utcnow() + timedelta(days=self.sla_days))
        self.store.add_request(req)
        return req

    def run(self, req: ErasureRequest, raise_errors: bool = False) -> dict:
        """Execute a request. Safe to call again after a crash: completed actions are skipped,
        the vault is not shredded twice, and a finished request returns its certificate."""
        with self.telemetry.span("dpdp.erasure", **{"dpdp.request_id": req.request_id, "dpdp.scope": req.scope,
                                                    "dpdp.principal": req.principal_id,
                                                    "dpdp.dry_run": req.dry_run}) as sp:
            t0 = time.monotonic()
            out = self._run(req, raise_errors)
            sp.set_attribute("dpdp.status", out.get("status", "unknown"))
            self.telemetry.requests.add(1, {"status": out.get("status", "unknown"), "scope": req.scope.split(":")[0]})
            if not req.dry_run:
                self.telemetry.duration.record(time.monotonic() - t0, {"scope": req.scope.split(":")[0]})
            return out

    def _run(self, req: ErasureRequest, raise_errors: bool) -> dict:
        pid = req.principal_id
        existing = self.store.get_request(req.request_id) or {}
        if str(existing.get("status", "")).startswith("completed"):
            cert = self.store.get_certificate(req.request_id)
            if cert:
                return json.loads(cert["payload"]) | {"certificate_sha256": cert["sha256"], "already_completed": True}
        if self.store.get_principal(pid) is None:
            self.store.set_request_status(req.request_id, RequestStatus.FAILED.value)
            return {"request_id": req.request_id, "status": "failed", "error": "unknown principal"}
        full = req.scope == "full"
        if not req.dry_run and full:
            self.store.set_principal_status(pid, PrincipalStatus.ERASURE_PENDING)
        prior = [] if req.dry_run else self.store.actions_for(req.request_id)
        prior_shred = next((a for a in prior if a["artifact_id"] == "vault" and a["action"] == "crypto_shred"), None)

        ctx = ErasureContext(pid, self.vault.tokens_for(pid), self.vault.snapshot_values(pid), req.dry_run)
        if prior_shred:   # resumed after the key was destroyed: recover the token list from lineage
            ctx.tokens = sorted({e.token for e in self.store.elements_for(pid) if e.token})
        try:
            plan = self.plan(ctx, req.scope)
            self.store.set_request_status(req.request_id, RequestStatus.PLANNED.value)
            if req.dry_run:
                for p in plan:
                    self.store.add_action(req.request_id, ActionResult(
                        p.artifact.artifact_id, p.artifact.store, p.action.value, True,
                        {"dry_run": True, "reason": p.reason, "kind": p.artifact.kind}))
                return self._summary(req, plan, [], [], None, status="planned")

            self.store.set_request_status(req.request_id, RequestStatus.EXECUTING.value)
            results = self.execute(req, plan, ctx)

            shred = (prior_shred or {}).get("detail")
            if full and not prior_shred:
                hold_tokens = set()
                for p in plan:
                    if p.action == Action.RETAIN_LEGAL_HOLD:
                        hold_tokens |= set(self.store.tokens_in_artifact_for(p.artifact.artifact_id, pid))
                last = self.store.last_processed_at(pid)
                shred = self.vault.shred(pid, retain_tokens=hold_tokens, escrow=self.retention.enabled)
                if shred.get("escrow_id"):
                    base = last if last and last.tzinfo else (last.replace(tzinfo=utcnow().tzinfo) if last else utcnow())
                    purge_after = base + timedelta(days=self.retention.days)
                    self.store.add_escrow(shred["escrow_id"], pid, req.request_id, self.retention.basis, purge_after)
                    shred["escrow_purge_after"] = purge_after.isoformat()
                    shred["escrow_basis"] = self.retention.basis
                self.store.add_action(req.request_id, ActionResult("vault", "vault", Action.CRYPTO_SHRED.value, True, shred))

            self.store.set_request_status(req.request_id, RequestStatus.VERIFYING.value)
            verification = self.verify(ctx, full)
            ok = all(r.ok for r in results) and all(v["ok"] for v in verification)
            status = RequestStatus.COMPLETED if ok else RequestStatus.COMPLETED_WITH_EXCEPTIONS
            if full:
                self.store.set_principal_status(pid, PrincipalStatus.ERASED)
            summary = self._summary(req, plan, results, verification, shred, status=status.value)
            if prior:
                summary["resumed"] = True
            self._certify(req, summary)
            self.store.set_request_status(req.request_id, status.value)
            return summary
        except Exception as e:  # noqa: BLE001
            log.exception("erasure failed")
            if raise_errors:         # let the job queue retry; the run resumes where it stopped
                raise
            self.store.set_request_status(req.request_id, RequestStatus.FAILED.value)
            return {"request_id": req.request_id, "status": "failed", "error": str(e)}
        finally:
            ctx.probes.clear()   # raw values never outlive the run

    # ------------------------------------------------------------------
    def _principal_ref_element(self, pid: str) -> str:
        for el in self.store.elements_for(pid):
            if el.element_type == "PRINCIPAL_REF":
                return el.element_id
        el = DataElement(new_id("el"), pid, "PRINCIPAL_REF", None)
        self.store.add_element(el)
        return el.element_id

    def discover(self, ctx: ErasureContext) -> list[Artifact]:
        """Native discovery in each connector; unregistered hits are added to lineage."""
        added = []
        for name, conn in self.connectors.items():
            try:
                hits = conn.discover(ctx)
            except Exception as e:  # noqa: BLE001
                log.warning("discovery failed for %s: %s", name, e)
                continue
            for d in hits:
                if self.store.find_artifact(name, d.locator):
                    continue
                a = Artifact(new_id("art"), d.kind, name, d.locator)
                self.store.add_artifact(a, element_ids=[self._principal_ref_element(ctx.principal_id)])
                added.append(a)
        return added

    def plan(self, ctx: ErasureContext, scope: str = "full") -> list[PlannedAction]:
        self.discover(ctx)
        entries = self.store.downstream(ctx.principal_id)
        purpose_filter = scope.split(":", 1)[1] if scope.startswith("purpose:") else None
        plan: list[PlannedAction] = []
        for e in entries:
            a: Artifact = e["artifact"]
            if a.status in (ArtifactStatus.ERASED.value,):
                continue
            if purpose_filter and a.purpose_id != purpose_filter:
                continue
            principals = self.store.principals_behind(a.artifact_id)
            owners = self.store.owners_of(a.artifact_id)
            third_only = bool(owners) and ctx.principal_id not in owners
            purpose = self.store.get_purpose(a.purpose_id) if a.purpose_id else None
            action, reason = self.policy.decide(PolicyInput(a, e["edge_type"], e["depth"], len(principals),
                                                            purpose, third_only))
            plan.append(PlannedAction(a, action, reason, e["edge_type"], e["depth"]))
        plan.sort(key=lambda p: (_PHASE[p.action], p.depth))
        return plan

    def execute(self, req: ErasureRequest, plan: list[PlannedAction], ctx: ErasureContext) -> list[ActionResult]:
        results = []
        done = {a["artifact_id"] for a in self.store.actions_for(req.request_id) if a["ok"]}
        for p in plan:
            a = p.artifact
            if a.artifact_id in done:        # resumed run: already handled
                continue
            conn = self.connectors.get(a.store)
            try:
                if p.action in (Action.RETAIN_LEGAL_HOLD, Action.FLAG_RETRAIN, Action.SKIP):
                    res = ActionResult(a.artifact_id, a.store, p.action.value, True, {"reason": p.reason})
                elif conn is None:
                    res = ActionResult(a.artifact_id, a.store, p.action.value, False,
                                       {"error": f"no connector configured for store '{a.store}'"})
                elif p.action == Action.REGENERATE:
                    res = self._regenerate(a, ctx, conn)
                elif p.action == Action.RETAIN_AGGREGATE:
                    res = conn.erase(a, Action.REDACT, ctx) if Action.REDACT in conn.supports else \
                        ActionResult(a.artifact_id, a.store, p.action.value, True, {"reason": p.reason})
                    res.action = Action.RETAIN_AGGREGATE.value
                else:
                    res = conn.erase(a, p.action, ctx)
            except Exception as e:  # noqa: BLE001
                res = ActionResult(a.artifact_id, a.store, p.action.value, False, {"error": str(e)})
            res.detail.setdefault("reason", p.reason)
            res.detail.setdefault("kind", a.kind)
            self.telemetry.actions.add(1, {"action": res.action, "store": a.store, "ok": res.ok})
            if res.ok:
                done = Action(res.action) if res.action in Action._value2member_map_ else p.action
                self.store.set_artifact_status(a.artifact_id, _STATUS_AFTER.get(done, ArtifactStatus.ERASED).value)
            self.store.add_action(req.request_id, res)
            results.append(res)
        return results

    def _regenerate(self, a: Artifact, ctx: ErasureContext, conn: Connector) -> ActionResult:
        fn = self.regenerators.get(a.store) or self.regenerators.get(a.kind)
        if fn:
            new = fn(a, ctx, self)
        else:
            new = self._default_regenerate(a, ctx, conn)
        if new is None:
            return conn.erase(a, Action.DELETE, ctx)
        new = redact_tokens(new, ctx.tokens)  # hard guarantee: no surviving tokens
        res = conn.replace(a, new, ctx)
        if not res.ok:
            return conn.erase(a, Action.REDACT, ctx)
        return res

    def _default_regenerate(self, a: Artifact, ctx: ErasureContext, conn: Connector) -> str | None:
        """Rebuild from surviving parents when we can fetch them; otherwise LLM-rewrite current content."""
        parents = []
        instruction = a.locator.get("regen_instruction")
        for pid_ in self.store.parents_of(a.artifact_id):
            pa = self.store.get_artifact(pid_)
            if not pa or pa.status == ArtifactStatus.ERASED.value:
                continue
            pconn = self.connectors.get(pa.store)
            content = pconn.fetch(pa) if pconn else None
            if content:
                parents.append(content)
        if instruction and self.provider is not None:
            if not parents:
                return None
            return self.provider.generate("\n\n---\n\n".join(parents), system=instruction).text
        current = conn.fetch(a)
        if current is None:
            return None
        if self.provider is None:
            return redact_tokens(current, ctx.tokens)
        prompt = f"Tokens to remove: {', '.join(ctx.tokens)}\n\nContent:\n{current}"
        return self.provider.generate(prompt, system=REGEN_SYSTEM).text

    def verify(self, ctx: ErasureContext, full: bool) -> list[dict]:
        out = []
        kept = {ArtifactStatus.RETAINED.value, ArtifactStatus.PENDING_RETRAIN.value}
        for name, conn in self.connectors.items():
            try:
                v = conn.verify(ctx)
                findings = []
                for f in v.findings:
                    a = self.store.find_artifact(name, f["locator"]) if isinstance(f.get("locator"), dict) else None
                    if a is None or a.status not in kept:      # sealed legal-hold / retained items are expected
                        findings.append(f)
                out.append({"store": name, "ok": not findings, "findings": findings[:20], "note": v.note})
            except Exception as e:  # noqa: BLE001
                out.append({"store": name, "ok": False, "findings": [], "note": f"verify error: {e}"})
        if full:
            readable = [t for t in ctx.tokens if self.vault.detokenize(t) is not None]
            note = "principal key destroyed; tokens unreadable by applications"
            if self.retention.enabled:
                note += f"; sealed escrow copy kept for statutory retention ({self.retention.days} days)"
            out.append({"store": "vault", "ok": not readable and not self.vault.has_key(ctx.principal_id),
                        "findings": [{"still_readable": len(readable)}] if readable else [], "note": note})
        return out

    # ------------------------------------------------------------------
    def purge_due_escrows(self, now=None) -> list[dict]:
        """Run on a schedule (EventBridge / Cloud Scheduler / cron): destroy escrow keys whose window ended."""
        now = now or utcnow()
        out = []
        for e in self.store.due_escrows(now):
            res = self.vault.destroy(e["escrow_id"])
            self.store.mark_escrow_purged(e["escrow_id"])
            if e.get("request_id"):
                self.store.add_action(e["request_id"], ActionResult("vault", "vault", "escrow_purged", True, res))
            out.append(res | {"principal_id": e["principal_id"]})
        return out

    def _summary(self, req, plan, results, verification, shred, status) -> dict:
        by_action: dict[str, int] = {}
        for r in (results or [ActionResult(p.artifact.artifact_id, p.artifact.store, p.action.value, True) for p in plan]):
            by_action[r.action] = by_action.get(r.action, 0) + 1
        exceptions = [
            {"artifact_id": p.artifact.artifact_id, "store": p.artifact.store, "kind": p.artifact.kind,
             "action": p.action.value, "reason": p.reason}
            for p in plan if p.action in (Action.RETAIN_LEGAL_HOLD, Action.RETAIN_AGGREGATE, Action.FLAG_RETRAIN)
        ]
        if shred and shred.get("escrow_id"):
            exceptions.append({"store": "vault", "kind": "retention_escrow", "action": "sealed_retention",
                               "reason": shred["escrow_basis"], "purge_after": shred["escrow_purge_after"]})
        failures = [r.__dict__ | {"executed_at": r.executed_at.isoformat()} for r in results if not r.ok]
        return {
            "request_id": req.request_id,
            "principal_id": req.principal_id,
            "scope": req.scope,
            "dry_run": req.dry_run,
            "status": status,
            "received_at": req.received_at.isoformat(),
            "due_by": req.due_by.isoformat() if req.due_by else None,
            "completed_at": utcnow().isoformat(),
            "artifacts_in_scope": len(plan),
            "actions": by_action,
            "plan": [{"artifact_id": p.artifact.artifact_id, "store": p.artifact.store, "kind": p.artifact.kind,
                      "edge": p.edge_type or "direct", "depth": p.depth, "action": p.action.value,
                      "reason": p.reason} for p in plan],
            "exceptions": exceptions,
            "failures": failures,
            "vault": shred,
            "verification": verification,
        }

    def _certify(self, req: ErasureRequest, summary: dict) -> None:
        prev = self.store.last_certificate_hash()
        body = {k: v for k, v in summary.items() if k != "plan"}
        body["prev_certificate_sha256"] = prev
        payload = json.dumps(body, sort_keys=True, default=str)
        digest = hashlib.sha256(payload.encode()).digest()
        sha = digest.hex()
        signature = signer_id = archive_uri = None
        if self.signer is not None:
            from ..security.signing import b64

            signature, signer_id = b64(self.signer.sign(digest)), self.signer.key_id
        if self.archive is not None:
            doc = json.dumps({"payload": json.loads(payload), "sha256": sha, "signature": signature,
                              "signer": signer_id}, sort_keys=True, default=str).encode()
            archive_uri = self.archive.put(f"{req.request_id}.json", doc)
        self.store.add_certificate(req.request_id, payload, sha, prev, signature, signer_id, archive_uri)
        summary["certificate_sha256"] = sha
        summary["certificate_signature"] = signature
        summary["certificate_archive"] = archive_uri
