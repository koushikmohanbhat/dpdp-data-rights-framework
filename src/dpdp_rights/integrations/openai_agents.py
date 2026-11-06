"""OpenAI Agents SDK integration: tokenise what reaches the model and what sessions store, and record lineage.

    from agents import Agent, Runner, SQLiteSession
    from dpdp_rights.integrations.openai_agents import ProtectedSession, run_config

    session = ProtectedSession(SQLiteSession(f"user-{pid}", "memory.db"), dpdp, principal_id=pid,
                               purpose="policy_issuance")
    with dpdp.context(pid, "policy_issuance"):
        result = await Runner.run(agent, user_text, session=session, run_config=run_config(dpdp))
        shown = dpdp.reveal(result.final_output)        # detokenise only for display to this person

* ``protect_model_input`` is a ``RunConfig.call_model_input_filter``: before every model call it tokenises every
  input item (user turns, tool outputs, earlier assistant turns) and checks consent for the purpose.
* ``ProtectedSession`` wraps any ``Session`` so the conversation memory it stores holds tokens, and registers the
  session in lineage for the ``openai_agents_sessions`` connector.
* ``run_config`` builds a RunConfig with the filter and with ``trace_include_sensitive_data`` off: the SDK's own
  traces record run inputs and tool outputs before any filter runs.

Who the data is about: the active ``dpdp.context(...)``, else the run context's ``dpdp_principal_id`` and
``dpdp_purpose`` (attributes or dict keys). Without one, the filter refuses to call the model.
"""
from __future__ import annotations

from typing import Any

from ..core.context import ContextEnvelope
from ._common import PRINCIPAL_KEY, Tokeniser, active, envelope_from

try:  # optional dependency: pip install "dpdp-data-rights-framework[openai-agents]"
    from agents import RunConfig
    from agents.run import CallModelData, ModelInputData
except ImportError as e:  # pragma: no cover
    raise ImportError('OpenAI Agents SDK integration needs: pip install "dpdp-data-rights-framework[openai-agents]"') \
        from e

STORE = "openai_agents_sessions"


class MissingContext(RuntimeError):
    """No Data Principal is known for this call."""


def protect_model_input(dpdp, *, default_purpose: str | None = None, enforce_consent: bool | None = None):
    """A ``call_model_input_filter`` that tokenises every input item before each model call."""
    enforce = dpdp.config.enforce_consent if enforce_consent is None else enforce_consent

    def _filter(data: CallModelData[Any]) -> ModelInputData:
        env = envelope_from(data.context, default_purpose=default_purpose)
        if env is None:
            raise MissingContext("no Data Principal for this model call: run inside dpdp.context(...) or put "
                                 f"{PRINCIPAL_KEY} and dpdp_purpose in the run context")
        with active(env):
            tok = Tokeniser(dpdp, enforce_consent=enforce)
            items = tok.walk(list(data.model_data.input))
        return ModelInputData(input=items, instructions=data.model_data.instructions)

    return _filter


def run_config(dpdp, *, default_purpose: str | None = None, **kw) -> RunConfig:
    """RunConfig with ``protect_model_input`` and sensitive trace data off (override with keyword arguments)."""
    kw.setdefault("trace_include_sensitive_data", False)
    return RunConfig(call_model_input_filter=protect_model_input(dpdp, default_purpose=default_purpose), **kw)


class ProtectedSession:
    """Wrap a Session so stored items hold tokens, and register the session in lineage."""

    def __init__(self, inner, dpdp, *, principal_id: str | None = None, purpose: str | None = None,
                 store: str = STORE):
        self.inner, self.dpdp, self.store = inner, dpdp, store
        self.session_id = inner.session_id
        self.session_settings = getattr(inner, "session_settings", None)
        self._env = ContextEnvelope(principal_id, purpose) if principal_id and purpose else None
        if principal_id and not purpose:
            raise ValueError("principal_id given without purpose: say why the data is processed")
        self._tok = Tokeniser(dpdp, enforce_consent=False)    # consent is checked before the model call
        self._registered = False

    async def add_items(self, items: list) -> None:
        env = self._env or envelope_from(None)
        if env is None:
            raise MissingContext("session written with no Data Principal: pass principal_id and purpose, or run "
                                 "inside dpdp.context(...)")
        with active(env):
            safe = self._tok.walk(list(items))
            els = self._tok.take_elements()
            if els or not self._registered:
                self.dpdp.touch_artifact("agent_session", self.store, {"session_id": self.session_id},
                                         element_ids=els, purpose=env.purpose_id)
                self._registered = True
        await self.inner.add_items(safe)

    async def get_items(self, limit: int | None = None) -> list:
        return await self.inner.get_items(limit)

    async def pop_item(self):
        return await self.inner.pop_item()

    async def clear_session(self) -> None:
        await self.inner.clear_session()

    def __getattr__(self, name):        # close(), backend-specific helpers
        return getattr(self.inner, name)
