"""Connector framework. A connector knows how to discover, erase and verify
personal data in one kind of store (CloudWatch Logs, AgentCore Memory, a
vector index, an eval dataset, ...)."""
from __future__ import annotations

import re
from abc import ABC
from dataclasses import dataclass, field
from typing import Any, Callable

from ..core.models import Action, ActionResult, Artifact
from ..vault.vault import ERASED_MARKER

_REGISTRY: dict[str, type["Connector"]] = {}


def register(type_name: str) -> Callable[[type["Connector"]], type["Connector"]]:
    def deco(cls: type["Connector"]) -> type["Connector"]:
        cls.type_name = type_name
        _REGISTRY[type_name] = cls
        return cls
    return deco


def registry() -> dict[str, type["Connector"]]:
    return dict(_REGISTRY)


@dataclass
class ErasureContext:
    principal_id: str
    tokens: list[str]                       # all vault tokens owned by the principal
    probes: dict[str, str] = field(default_factory=dict)  # token -> raw value, in memory only
    dry_run: bool = False

    @property
    def needles(self) -> list[str]:
        """Strings that must not survive erasure: principal id + tokens."""
        return [self.principal_id, *self.tokens]


@dataclass
class Discovered:
    kind: str
    locator: dict[str, Any]
    note: str | None = None


@dataclass
class VerifyResult:
    store: str
    ok: bool
    findings: list[dict[str, Any]] = field(default_factory=list)
    note: str | None = None


def redact_tokens(text: str, tokens: list[str]) -> str:
    if not tokens:
        return text
    pat = re.compile("|".join(re.escape(t) for t in tokens))
    return pat.sub(ERASED_MARKER, text)


class Connector(ABC):
    type_name: str = "base"
    #: actions this connector can perform natively
    supports: set[Action] = {Action.DELETE}

    def __init__(self, name: str, **options: Any):
        self.name = name
        self.options = options

    # Native discovery catches artifacts that were never registered in lineage
    # (e.g. written by code that bypassed the SDK). Optional.
    def discover(self, ctx: ErasureContext) -> list[Discovered]:
        return []

    def erase(self, artifact: Artifact, action: Action, ctx: ErasureContext) -> ActionResult:
        if action not in self.supports:
            # Fall back: anything we can't redact/regenerate in place we delete.
            if Action.DELETE in self.supports and action in (Action.REDACT, Action.REGENERATE):
                return self._delete(artifact, ctx, fallback_from=action)
            return ActionResult(artifact.artifact_id, self.name, action.value, False,
                                {"error": f"{self.type_name} does not support {action.value}"})
        handler = getattr(self, f"_{action.value}")
        return handler(artifact, ctx)

    def replace(self, artifact: Artifact, new_content: str, ctx: ErasureContext) -> ActionResult:
        return ActionResult(artifact.artifact_id, self.name, "regenerate", False,
                            {"error": f"{self.type_name} cannot replace content"})

    def fetch(self, artifact: Artifact) -> str | None:
        """Return artifact content (tokenised) when the store holds text; used for regeneration."""
        return None

    def verify(self, ctx: ErasureContext) -> VerifyResult:
        found = self.discover(ctx)
        return VerifyResult(self.name, not found, [d.__dict__ for d in found])

    # default handlers ------------------------------------------------------
    def _delete(self, artifact: Artifact, ctx: ErasureContext, fallback_from: Action | None = None) -> ActionResult:
        raise NotImplementedError

    def _crypto_shred(self, artifact: Artifact, ctx: ErasureContext) -> ActionResult:
        return ActionResult(artifact.artifact_id, self.name, Action.CRYPTO_SHRED.value, True,
                            {"note": "Content holds vault tokens only; unreadable once the principal key is destroyed."})

    def _ok(self, artifact: Artifact, action: Action | str, **detail) -> ActionResult:
        return ActionResult(artifact.artifact_id, self.name, getattr(action, "value", action), True, detail)

    def _skip(self, artifact: Artifact, action: Action, ctx: ErasureContext) -> ActionResult:
        return self._ok(artifact, action, dry_run=True)


def build_connectors(configs) -> dict[str, Connector]:
    # import side-effect registers built-ins
    from . import agents, anthropic_platform, aws, gcp, local, observability, openai_platform  # noqa: F401

    out = {}
    for c in configs:
        cls = _REGISTRY.get(c.type)
        if cls is None:
            raise ValueError(f"Unknown connector type '{c.type}'. Known: {sorted(_REGISTRY)}")
        out[c.name] = cls(c.name, **c.options)
    return out
