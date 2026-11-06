"""Decides what to do with each artifact reached by an erasure request.

Precedence:
 1. Legal hold on the artifact's purpose          -> RETAIN_LEGAL_HOLD
 2. First matching user rule in config             -> rule.action
 3. Built-in defaults:
      model weights                                -> FLAG_RETRAIN
      aggregate with >= k other principals         -> RETAIN_AGGREGATE
      aggregate below k / per-user summary         -> REGENERATE
      log / trace (immutable stores)               -> CRYPTO_SHRED
      third-party mention in someone else's record (or its derivatives) -> REDACT
 4. default_action (delete)
"""
from __future__ import annotations

from dataclasses import dataclass

from ..core.config import PolicyConfig
from ..core.models import Action, Artifact, Purpose


@dataclass
class PolicyInput:
    artifact: Artifact
    edge_type: str | None
    depth: int
    principals_behind: int
    purpose: Purpose | None
    principal_is_third_party_only: bool


class PolicyEngine:
    def __init__(self, cfg: PolicyConfig):
        self.cfg = cfg

    def decide(self, x: PolicyInput) -> tuple[Action, str]:
        a = x.artifact
        if x.purpose and x.purpose.legal_hold_basis:
            return Action.RETAIN_LEGAL_HOLD, f"Retention required: {x.purpose.legal_hold_basis}"

        for r in self.cfg.rules:
            if r.kind and r.kind != a.kind:
                continue
            if r.edge_type and r.edge_type != (x.edge_type or "direct"):
                continue
            if r.store and r.store != a.store:
                continue
            if r.purpose and r.purpose != a.purpose_id:
                continue
            if r.min_principals is not None and x.principals_behind < r.min_principals:
                continue
            return Action(r.action), r.reason or f"rule: {r.model_dump(exclude_none=True)}"

        k = self.cfg.aggregate_k_threshold
        if a.kind == "model" or x.edge_type == "train":
            if a.kind == "model":
                return Action.FLAG_RETRAIN, "Model weights may memorise training data; retrain without the principal"
        if x.principal_is_third_party_only and x.edge_type != "aggregate":
            return Action.REDACT, "Principal is only mentioned in another person's record"
        if x.edge_type == "aggregate" or (a.kind == "summary" and x.principals_behind > 1):
            if x.principals_behind - 1 >= k:
                return Action.RETAIN_AGGREGATE, f"Aggregate over {x.principals_behind} principals (k={k}); tokens redacted"
            return Action.REGENERATE, f"Aggregate below k={k}; rebuild without the principal's inputs"
        if a.kind == "summary":
            return Action.REGENERATE, "Per-user derived summary"
        if a.kind in ("log", "trace"):
            return Action.CRYPTO_SHRED, "Immutable store; content is tokenised"
        return Action(self.cfg.default_action), "default"
