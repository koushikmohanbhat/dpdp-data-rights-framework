"""Shared helpers for agent-framework integrations: who the data is about, and tokenising nested messages."""
from __future__ import annotations

import contextlib
from collections import OrderedDict
from collections.abc import Callable, Iterator, Mapping
from typing import Any

from ..core import context as ctxmod
from ..core.context import ContextEnvelope

PRINCIPAL_KEY = "dpdp_principal_id"
PURPOSE_KEY = "dpdp_purpose"

# Keys whose string values are structure, not content: never tokenise them.
STRUCTURAL_KEYS = frozenset({
    "id", "type", "role", "name", "call_id", "tool_call_id", "status", "model", "index", "thread_id",
    "checkpoint_id", "checkpoint_ns", "run_id", "response_id", "item_id", "previous_response_id", "format",
    "mime_type", "detail", "lc", "__type", "message_id", PRINCIPAL_KEY, PURPOSE_KEY,
})


def _get(obj: Any, key: str) -> Any:
    if obj is None:
        return None
    if isinstance(obj, Mapping):
        return obj.get(key)
    return getattr(obj, key, None)


def envelope_from(*sources: Any, default_purpose: str | None = None) -> ContextEnvelope | None:
    """The DPDP context for this call: the active ``dpdp.context(...)`` if any, else the first source (a
    run context object or dict, or a RunnableConfig's ``configurable``) carrying ``dpdp_principal_id``."""
    env = ctxmod.current()
    if env is not None:
        return env
    for src in sources:
        for cand in (src, _get(src, "configurable")):
            pid = _get(cand, PRINCIPAL_KEY)
            if pid:
                purpose = _get(cand, PURPOSE_KEY) or default_purpose
                if not purpose:
                    raise ValueError(f"{PRINCIPAL_KEY} given without {PURPOSE_KEY}: say why the data is processed")
                return ContextEnvelope(str(pid), str(purpose))
    return None


@contextlib.contextmanager
def active(env: ContextEnvelope | None) -> Iterator[ContextEnvelope | None]:
    """Make ``env`` the current context for the block, unless it already is."""
    if env is None or ctxmod.current() == env:
        yield env
        return
    tok = ctxmod.set_current(env)
    try:
        yield env
    finally:
        ctxmod.reset(tok)


class Tokeniser:
    """Tokenises strings inside nested structures (dicts, lists, LangChain messages), with a bounded memo so
    re-saving a growing conversation does not re-scan every earlier turn."""

    def __init__(self, dpdp, *, enforce_consent: bool = False, memo_size: int = 4096):
        self.dpdp, self.enforce_consent, self.memo_size = dpdp, enforce_consent, memo_size
        self._memo: OrderedDict[tuple[str, str], tuple[str, tuple[str, ...]]] = OrderedDict()
        self.element_ids: set[str] = set()

    def text(self, s: str) -> str:
        if not s or not s.strip():
            return s
        env = ctxmod.require()
        key = (env.principal_id, s)
        hit = self._memo.get(key)
        if hit is None:
            p = self.dpdp.protect(s, enforce_consent=self.enforce_consent)
            hit = (p.text, tuple(p.element_ids))
            self._memo[key] = hit
            if len(self._memo) > self.memo_size:
                self._memo.popitem(last=False)
        else:
            self._memo.move_to_end(key)
        self.element_ids.update(hit[1])
        return hit[0]

    def walk(self, value: Any, message_hook: Callable[[Any], Any] | None = None) -> Any:
        """Return a copy of ``value`` with every content string tokenised. ``message_hook`` handles framework
        message objects (it gets the object and returns a tokenised copy, or None to fall through)."""
        if isinstance(value, str):
            return self.text(value)
        if message_hook is not None:
            done = message_hook(value)
            if done is not None:
                return done
        if isinstance(value, dict):
            return {k: (v if k in STRUCTURAL_KEYS and isinstance(v, str) else self.walk(v, message_hook))
                    for k, v in value.items()}
        if isinstance(value, list):
            return [self.walk(v, message_hook) for v in value]
        if isinstance(value, tuple):
            return tuple(self.walk(v, message_hook) for v in value)
        return value

    def take_elements(self) -> list[str]:
        out, self.element_ids = sorted(self.element_ids), set()
        return out
