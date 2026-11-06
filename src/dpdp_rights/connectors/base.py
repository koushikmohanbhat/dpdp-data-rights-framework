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


BUILTIN_MODULES = ("agents", "anthropic_platform", "aws", "gcp", "local", "observability", "openai_platform")


def register(type_name: str) -> Callable[[type["Connector"]], type["Connector"]]:
    def deco(cls: type["Connector"]) -> type["Connector"]:
        from .. import plugins

        cls.type_name = type_name
        _REGISTRY[type_name] = cls
        plugins.register_builtin("connectors", type_name, cls)
        return cls
    return deco


def load_builtin_connectors() -> None:
    import importlib

    for m in BUILTIN_MODULES:
        importlib.import_module(f"{__package__}.{m}")


def connector_class(type_name: str) -> type["Connector"]:
    """A built-in connector class, or one installed as a plug-in (entry point group dpdp_rights.connectors)."""
    from .. import plugins

    load_builtin_connectors()
    if type_name in _REGISTRY:
        return _REGISTRY[type_name]
    cls = plugins.get("connectors", type_name)
    if not (isinstance(cls, type) and issubclass(cls, Connector)):
        raise ValueError(f"connector plug-in '{type_name}' must be a Connector subclass, got {cls!r}")
    cls.type_name = type_name
    _REGISTRY[type_name] = cls
    return cls


def load_all_connectors() -> None:
    """Built-ins plus every installed connector plug-in (for the capability matrix and coverage)."""
    from .. import plugins

    load_builtin_connectors()
    for name in plugins.available("connectors"):
        try:
            connector_class(name)
        except ValueError:
            pass   # reported by `dpdp-rights plugins`


def registry() -> dict[str, type["Connector"]]:
    return dict(_REGISTRY)


def capability_matrix() -> dict[str, dict]:
    """Capabilities of every registered connector type, keyed by type name."""
    return {name: (cls.capabilities.to_dict(cls.supports) if cls.capabilities else
                   {"store": name, "discover": "unknown", "discover_how": "not declared",
                    "actions": sorted(a.value for a in cls.supports), "verify": "unknown",
                    "verify_how": "not declared", "limits": ["capabilities not declared"],
                    "deletion": "item" if Action.DELETE in cls.supports else "none",
                    "individual_deletion": Action.DELETE in cls.supports,
                    "redact_in_place": Action.REDACT in cls.supports})
            for name, cls in sorted(_REGISTRY.items())}


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


@dataclass(frozen=True)
class Capabilities:
    """What a connector can and cannot do, so partners choose by capability, not by cloud name.

    discover: how it finds a person's data that nobody registered (``native`` search, or ``lineage``
              only, i.e. it acts only on artifacts registered with ``track_artifact``)
    verify:   how it checks the result (``rescan`` the store for tokens and raw values, ``rediscover``,
              ``api_confirmation`` from the service, ``action_status`` only, or ``none``)
    limits:   plain-language statements of what the service does not allow
    """
    store: str
    discover: str            # native | lineage
    discover_how: str
    verify: str              # rescan | rediscover | api_confirmation | action_status | none
    verify_how: str
    limits: tuple[str, ...] = ()
    #: what "delete" removes: one ``item``, a whole ``container`` (stream, file), ``revoke`` (access is
    #: revoked, nothing is deleted), or ``none``. Defaults to ``item`` when DELETE is supported.
    deletion: str | None = None

    def to_dict(self, supports: set) -> dict:
        actions = sorted(a.value for a in supports)
        deletion = self.deletion or ("item" if "delete" in actions else "none")
        return {"store": self.store, "discover": self.discover, "discover_how": self.discover_how,
                "actions": actions, "deletion": deletion, "individual_deletion": deletion == "item",
                "redact_in_place": "redact" in actions, "verify": self.verify, "verify_how": self.verify_how,
                "limits": list(self.limits)}


def redact_tokens(text: str, tokens: list[str]) -> str:
    if not tokens:
        return text
    pat = re.compile("|".join(re.escape(t) for t in tokens))
    return pat.sub(ERASED_MARKER, text)


class Connector(ABC):
    type_name: str = "base"
    #: actions this connector can perform natively
    supports: set[Action] = {Action.DELETE}
    #: declared capabilities and limits (shown by ``dpdp-rights capabilities`` and the coverage report)
    capabilities: Capabilities | None = None

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
    return {c.name: connector_class(c.type)(c.name, **c.options) for c in configs}
