"""Agent-framework memory: LangGraph checkpointers and OpenAI Agents SDK sessions (docs/agent-frameworks.md).

Both hold whole conversations. Written through ``integrations.langchain.ProtectedCheckpointer`` or
``integrations.openai_agents.ProtectedSession`` they hold tokens, not detected personal data, and every thread or
session is registered in lineage.

* The person's **own** threads and sessions are deleted.
* A thread that only **mentions** them (a nominee named in someone else's conversation) is kept: it holds only
  tokens, so destroying their key makes the mention unreadable, the same treatment as immutable logs.

Both connectors take the live object in code (``checkpointer=`` / ``session_factory=``) or, from config, a
``factory: "package.module:attribute"`` import path.
"""
from __future__ import annotations

import asyncio
import importlib
import json
import threading
from typing import Any

from ..core.models import Action
from .base import Capabilities, Connector, Discovered, VerifyResult, register

PRINCIPAL_KEY = "dpdp_principal_id"


def _load(path: str):
    mod, _, attr = path.partition(":")
    if not mod or not attr:
        raise ValueError(f"factory must look like 'package.module:attribute', got {path!r}")
    obj = importlib.import_module(mod)
    for part in attr.split("."):
        obj = getattr(obj, part)
    return obj


def _run(coro):
    """Run a coroutine from synchronous erasure code, even if an event loop is already running here."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    out: dict[str, Any] = {}

    def target():
        try:
            out["v"] = asyncio.run(coro)
        except BaseException as e:  # noqa: BLE001
            out["e"] = e
    t = threading.Thread(target=target)
    t.start()
    t.join()
    if "e" in out:
        raise out["e"]
    return out.get("v")


def _mention_only(self, artifact, ctx):
    return self._ok(artifact, Action.CRYPTO_SHRED,
                    note="the thread belongs to someone else and only mentions this person; it holds their tokens "
                         "only, which are unreadable once their key is destroyed")


@register("langgraph_checkpoints")
class LangGraphCheckpointConnector(Connector):
    supports = {Action.DELETE, Action.CRYPTO_SHRED, Action.REDACT}
    capabilities = Capabilities(
        store="LangGraph checkpointer threads (conversation state and history)",
        discover="native",
        discover_how="lists checkpoints and finds threads the person owns (owner recorded by ProtectedCheckpointer) "
                     "or that hold their raw values",
        verify="rescan", verify_how="lists checkpoints again: no owned thread and no raw value may remain",
        deletion="container",
        limits=(
            "deletes the whole thread (every checkpoint and pending write) with the checkpointer's delete_thread",
            "a thread that only mentions the person is kept; their tokens in it become unreadable when their key "
            "is destroyed",
            "discovery reads up to scan_limit checkpoints (default 20000); raise it or rely on lineage for "
            "larger stores",
        ))

    def __init__(self, name: str, checkpointer=None, factory: str | None = None, scan_limit: int = 20000, **kw):
        super().__init__(name, **kw)
        if checkpointer is None:
            if not factory:
                raise ValueError(f"{name}: pass checkpointer= or options.factory 'module:attribute'")
            obj = _load(factory)
            checkpointer = obj() if callable(obj) and not hasattr(obj, "put") else obj
        self.cp = getattr(checkpointer, "inner", checkpointer)    # read past a ProtectedCheckpointer
        self.scan_limit = int(scan_limit)

    def discover(self, ctx):
        raw = [v for v in ctx.probes.values() if v and len(v) >= 4]
        threads: dict[str, str] = {}
        for t in self.cp.list(None, limit=self.scan_limit):
            tid = str((t.config.get("configurable") or {}).get("thread_id"))
            if tid in threads:
                continue
            if (t.metadata or {}).get(PRINCIPAL_KEY) == ctx.principal_id:
                threads[tid] = "owned"
                continue
            if raw:
                blob = json.dumps(t.checkpoint.get("channel_values"), default=str, ensure_ascii=False)
                if any(v in blob for v in raw):
                    threads[tid] = "raw values"
        return [Discovered("conversation_thread", {"thread_id": tid}, note=why) for tid, why in threads.items()]

    def _delete(self, artifact, ctx, fallback_from=None):
        self.cp.delete_thread(artifact.locator["thread_id"])
        return self._ok(artifact, Action.DELETE, thread_id=artifact.locator["thread_id"])

    _redact = _mention_only


@register("openai_agents_sessions")
class AgentsSessionConnector(Connector):
    supports = {Action.DELETE, Action.CRYPTO_SHRED, Action.REDACT}
    capabilities = Capabilities(
        store="OpenAI Agents SDK sessions (conversation memory: SQLite, SQLAlchemy, Redis, OpenAI Conversations)",
        discover="lineage", discover_how="acts on sessions registered by ProtectedSession",
        verify="rediscover", verify_how="re-opens each session it cleared and checks that it is empty",
        deletion="container",
        limits=(
            "the Session interface cannot list sessions, so sessions written without ProtectedSession are not found",
            "a session that only mentions the person is kept; their tokens in it become unreadable when their key "
            "is destroyed",
        ))

    def __init__(self, name: str, session_factory=None, factory: str | None = None, **kw):
        super().__init__(name, **kw)
        if session_factory is None:
            if not factory:
                raise ValueError(f"{name}: pass session_factory= or options.factory 'module:attribute'")
            session_factory = _load(factory)
        self.session_factory = session_factory
        self._cleared: list[str] = []

    def _delete(self, artifact, ctx, fallback_from=None):
        sid = artifact.locator["session_id"]
        _run(self.session_factory(sid).clear_session())
        self._cleared.append(sid)
        return self._ok(artifact, Action.DELETE, session_id=sid)

    _redact = _mention_only

    def verify(self, ctx):
        left = [sid for sid in self._cleared if _run(self.session_factory(sid).get_items())]
        self._cleared = []
        return VerifyResult(self.name, not left, [{"session_id": s, "issue": "not empty after clear"} for s in left],
                            note="checked every session cleared in this run")
