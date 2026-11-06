"""LangChain / LangGraph integration: tokenise what reaches the model and what is saved, and record lineage.

Two pieces, used together (docs/agent-frameworks.md):

* ``DPDPMiddleware`` - a LangChain agent middleware (``create_agent(..., middleware=[...])``). Before each model
  call it tokenises every human, tool and system message in the agent state and writes the tokenised copies back
  (same message ids), so the model and every later step see tokens; consent is checked for the purpose. After
  the call it tokenises any raw personal data the model itself produced.
* ``ProtectedCheckpointer`` - wraps any LangGraph checkpointer. LangGraph saves the user's input in a checkpoint
  *before* any middleware runs, and checkpointers keep every checkpoint of a thread, so tokenising only in the
  middleware would leave raw values in history. The wrapper tokenises every checkpoint and pending write at
  save time, marks the thread's owner in checkpoint metadata, and registers the thread in lineage so the
  ``langgraph_checkpoints`` connector can erase it.

Who the data is about comes from the active ``dpdp.context(...)``, or from the run's context or
``configurable`` (``dpdp_principal_id`` and ``dpdp_purpose``). Without it the middleware refuses to run.
"""
from __future__ import annotations

from collections.abc import AsyncIterator, Iterator, Sequence
from typing import Any

from ._common import PRINCIPAL_KEY, Tokeniser, active, envelope_from

try:  # optional dependency: pip install "dpdp-data-rights-framework[langchain]"
    from langchain.agents.middleware import AgentMiddleware
    from langchain_core.messages import AIMessage, BaseMessage
    from langgraph.checkpoint.base import BaseCheckpointSaver
except ImportError as e:  # pragma: no cover - exercised only without the extra
    raise ImportError('LangChain integration needs: pip install "dpdp-data-rights-framework[langchain]"') from e

STORE = "langgraph_checkpoints"


class MissingContext(RuntimeError):
    """No Data Principal is known for this call."""


def _message_hook(tok: Tokeniser):
    def hook(v):
        if isinstance(v, BaseMessage):
            content = tok.walk(v.content)
            return v if content == v.content else v.model_copy(update={"content": content})
        return None
    return hook


class DPDPMiddleware(AgentMiddleware):
    """Tokenise messages before every model call; tokenise new personal data in the model's reply."""

    def __init__(self, dpdp, *, default_purpose: str | None = None, enforce_consent: bool | None = None):
        super().__init__()
        self.dpdp, self.default_purpose = dpdp, default_purpose
        self.enforce_consent = dpdp.config.enforce_consent if enforce_consent is None else enforce_consent

    def _env(self, runtime):
        try:
            from langgraph.config import get_config
            cfg = get_config()
        except Exception:  # noqa: BLE001 - outside a graph run
            cfg = None
        env = envelope_from(getattr(runtime, "context", None), cfg, default_purpose=self.default_purpose)
        if env is None:
            raise MissingContext("no Data Principal for this agent call: run it inside dpdp.context(...) or pass "
                                 f"{PRINCIPAL_KEY} and dpdp_purpose in the run context or configurable")
        return env

    def _rewrite(self, messages, *, only_ai: bool, enforce: bool):
        tok = Tokeniser(self.dpdp, enforce_consent=enforce)
        hook, changed = _message_hook(tok), []
        for m in messages:
            if isinstance(m, AIMessage) != only_ai:
                continue
            new = hook(m)
            if new is not m:
                changed.append(new)
        return changed

    def before_model(self, state, runtime):
        with active(self._env(runtime)):
            changed = self._rewrite(state.get("messages", []), only_ai=False, enforce=self.enforce_consent)
        return {"messages": changed} if changed else None

    def after_model(self, state, runtime):
        msgs = state.get("messages", [])
        if not msgs or not isinstance(msgs[-1], AIMessage):
            return None
        with active(self._env(runtime)):
            changed = self._rewrite(msgs[-1:], only_ai=True, enforce=False)
        return {"messages": changed} if changed else None

    async def abefore_model(self, state, runtime):
        return self.before_model(state, runtime)

    async def aafter_model(self, state, runtime):
        return self.after_model(state, runtime)


class ProtectedCheckpointer(BaseCheckpointSaver):
    """Wrap a checkpointer so nothing it saves holds detected personal data in the clear, and every thread is in
    lineage. Reads, listing and deletion pass straight through."""

    def __init__(self, inner: BaseCheckpointSaver, dpdp, *, store: str = STORE, default_purpose: str | None = None):
        super().__init__(serde=inner.serde)
        self.inner, self.dpdp, self.store, self.default_purpose = inner, dpdp, store, default_purpose
        self._tok = Tokeniser(dpdp, enforce_consent=False)   # consent is checked before the model call
        self._seen: set[tuple[str, str]] = set()

    # ---- writes: tokenise, mark the owner, register the thread -------------------------------------------
    def _protect(self, config, value):
        env = envelope_from(config, default_purpose=self.default_purpose)
        if env is None:
            raise MissingContext("checkpoint written with no Data Principal: run the graph inside dpdp.context(...) "
                                 f"or pass {PRINCIPAL_KEY} and dpdp_purpose in configurable")
        with active(env):
            out = self._tok.walk(value, _message_hook(self._tok))
            els = self._tok.take_elements()
            tid = str((config.get("configurable") or {}).get("thread_id"))
            if els or (env.principal_id, tid) not in self._seen:
                self.dpdp.touch_artifact("conversation_thread", self.store, {"thread_id": tid}, element_ids=els,
                                         purpose=env.purpose_id)
                self._seen.add((env.principal_id, tid))
        return out, env

    def _checkpoint(self, config, checkpoint, metadata):
        values, env = self._protect(config, checkpoint.get("channel_values", {}))
        return {**checkpoint, "channel_values": values}, {**(metadata or {}), PRINCIPAL_KEY: env.principal_id}

    def put(self, config, checkpoint, metadata, new_versions):
        cp, md = self._checkpoint(config, checkpoint, metadata)
        return self.inner.put(config, cp, md, new_versions)

    async def aput(self, config, checkpoint, metadata, new_versions):
        cp, md = self._checkpoint(config, checkpoint, metadata)
        return await self.inner.aput(config, cp, md, new_versions)

    def _writes(self, config, writes: Sequence[tuple[str, Any]]):
        return [(ch, self._protect(config, v)[0]) for ch, v in writes]

    def put_writes(self, config, writes, task_id, task_path=""):
        return self.inner.put_writes(config, self._writes(config, writes), task_id, task_path)

    async def aput_writes(self, config, writes, task_id, task_path=""):
        return await self.inner.aput_writes(config, self._writes(config, writes), task_id, task_path)

    # ---- everything else passes through ------------------------------------------------------------------
    def get_tuple(self, config):
        return self.inner.get_tuple(config)

    async def aget_tuple(self, config):
        return await self.inner.aget_tuple(config)

    def list(self, config, *, filter=None, before=None, limit=None) -> Iterator:
        return self.inner.list(config, filter=filter, before=before, limit=limit)

    async def alist(self, config, *, filter=None, before=None, limit=None) -> AsyncIterator:
        async for x in self.inner.alist(config, filter=filter, before=before, limit=limit):
            yield x

    def delete_thread(self, thread_id: str) -> None:
        return self.inner.delete_thread(thread_id)

    async def adelete_thread(self, thread_id: str) -> None:
        return await self.inner.adelete_thread(thread_id)

    def get_next_version(self, current, channel):
        return self.inner.get_next_version(current, channel)

    def copy_thread(self, source_thread_id, target_thread_id):
        return self.inner.copy_thread(source_thread_id, target_thread_id)

    async def acopy_thread(self, source_thread_id, target_thread_id):
        return await self.inner.acopy_thread(source_thread_id, target_thread_id)

    def prune(self, thread_ids, *, strategy="keep_latest"):
        return self.inner.prune(thread_ids, strategy=strategy)

    async def aprune(self, thread_ids, *, strategy="keep_latest"):
        return await self.inner.aprune(thread_ids, strategy=strategy)

    def delete_for_runs(self, run_ids):
        return self.inner.delete_for_runs(run_ids)

    async def adelete_for_runs(self, run_ids):
        return await self.inner.adelete_for_runs(run_ids)

    @property
    def config_specs(self):
        return self.inner.config_specs
