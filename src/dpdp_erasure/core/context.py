"""Context envelope propagated through agents, tools and pipelines.

Every hop carries: who the data is about (pseudonymous principal id), why it
is being processed (purpose), and which artifacts it came from (parents).
It can be serialised to W3C ``baggage`` headers so it survives HTTP hops,
AgentCore Runtime invocations, queues, etc.
"""
from __future__ import annotations

import contextvars
from dataclasses import dataclass, field, replace
from urllib.parse import quote, unquote

_current: contextvars.ContextVar["ContextEnvelope | None"] = contextvars.ContextVar(
    "dpdp_envelope", default=None
)

BAGGAGE_PREFIX = "dpdp."


@dataclass(frozen=True)
class ContextEnvelope:
    principal_id: str
    purpose_id: str
    session_id: str | None = None
    parent_artifact_ids: tuple[str, ...] = field(default_factory=tuple)
    tenant: str | None = None

    def with_parents(self, *artifact_ids: str) -> "ContextEnvelope":
        return replace(self, parent_artifact_ids=tuple(artifact_ids))

    # ---- W3C baggage serialisation ------------------------------------
    def to_baggage(self) -> str:
        items = {
            "principal": self.principal_id,
            "purpose": self.purpose_id,
            "session": self.session_id or "",
            "parents": ",".join(self.parent_artifact_ids),
            "tenant": self.tenant or "",
        }
        return ",".join(f"{BAGGAGE_PREFIX}{k}={quote(v, safe='')}" for k, v in items.items() if v)

    def to_headers(self) -> dict[str, str]:
        return {"baggage": self.to_baggage()}

    @classmethod
    def from_baggage(cls, baggage: str) -> "ContextEnvelope | None":
        values: dict[str, str] = {}
        for part in baggage.split(","):
            if "=" not in part:
                continue
            k, v = part.strip().split("=", 1)
            if k.startswith(BAGGAGE_PREFIX):
                values[k[len(BAGGAGE_PREFIX):]] = unquote(v.split(";")[0])
        if "principal" not in values or "purpose" not in values:
            return None
        parents = tuple(p for p in values.get("parents", "").split(",") if p)
        return cls(
            principal_id=values["principal"],
            purpose_id=values["purpose"],
            session_id=values.get("session") or None,
            parent_artifact_ids=parents,
            tenant=values.get("tenant") or None,
        )

    @classmethod
    def from_headers(cls, headers: dict[str, str]) -> "ContextEnvelope | None":
        for k, v in headers.items():
            if k.lower() == "baggage":
                return cls.from_baggage(v)
        return None


def current() -> ContextEnvelope | None:
    return _current.get()


def require() -> ContextEnvelope:
    env = _current.get()
    if env is None:
        raise RuntimeError(
            "No DPDP context envelope active. Wrap processing in `with kit.context(...)`."
        )
    return env


def set_current(env: ContextEnvelope | None) -> contextvars.Token:
    return _current.set(env)


def reset(token: contextvars.Token) -> None:
    _current.reset(token)
