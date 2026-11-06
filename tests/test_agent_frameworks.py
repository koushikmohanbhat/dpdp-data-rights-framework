"""LangChain/LangGraph and OpenAI Agents SDK integrations (docs/agent-frameworks.md), with fake models."""
import asyncio
import json
import os

os.environ.setdefault("OPENAI_AGENTS_DISABLE_TRACING", "1")    # no trace export from tests

import pytest
from test_rights import _cfg

from dpdp_rights import DataRightsFramework
from dpdp_rights.consent.ledger import ConsentDenied

RAW = ("rahul@example.in", "9876543210", "priya@example.in", "9123456780")


def _fw(tmp, **conn):
    f = DataRightsFramework(_cfg(tmp))
    for name, c in conn.items():
        f.connectors[name] = c
    return f


def _people(f):
    rahul = f.principal("rahul")
    f.grant_consent(rahul, "service")
    priya = f.principal("priya")
    f.register_identifier(priya, "EMAIL", "priya@example.in")
    return rahul, priya


# ==== LangChain / LangGraph ===================================================================================
lc = pytest.importorskip("langchain.agents")
from langchain.agents import create_agent  # noqa: E402
from langchain_core.language_models.fake_chat_models import FakeMessagesListChatModel  # noqa: E402
from langchain_core.messages import AIMessage  # noqa: E402
from langgraph.checkpoint.memory import InMemorySaver  # noqa: E402

from dpdp_rights.connectors.frameworks import LangGraphCheckpointConnector  # noqa: E402
from dpdp_rights.integrations.langchain import DPDPMiddleware, MissingContext, ProtectedCheckpointer  # noqa: E402


class SpyModel(FakeMessagesListChatModel):
    seen: list = []

    def _generate(self, messages, *a, **k):
        type(self).seen.append([m.content for m in messages])
        return super()._generate(messages, *a, **k)


def _agent(f, saver, replies=("ok",), middleware=True):
    SpyModel.seen = []
    model = SpyModel(responses=[AIMessage(content=r) for r in replies])
    return create_agent(model, tools=[], middleware=[DPDPMiddleware(f)] if middleware else [],
                        checkpointer=ProtectedCheckpointer(saver, f))


def _saver_text(saver):
    return repr(saver.storage) + repr(saver.writes) + repr(getattr(saver, "blobs", {}))


def test_model_and_every_checkpoint_see_tokens_only(workdir):
    tmp, _ = workdir
    f, saver = _fw(tmp), InMemorySaver()
    rahul, _ = _people(f)
    agent = _agent(f, saver, replies=["We will call you on 9123456780"])
    with f.context(rahul, "service"):
        out = agent.invoke({"messages": [{"role": "user", "content": "I'm Rahul, rahul@example.in, 9876543210"}]},
                           {"configurable": {"thread_id": "t1"}})
        shown = f.reveal(out["messages"][-1].content)
    sent = json.dumps(SpyModel.seen)
    assert not any(v in sent for v in RAW) and "<EMAIL_" in sent and "<PHONE_IN_" in sent
    assert not any(v in _saver_text(saver) for v in RAW)          # input checkpoint, writes and history
    assert "<PHONE_IN_" in out["messages"][-1].content and shown.endswith("9123456780")
    art = f.store.find_artifact("langgraph_checkpoints", {"thread_id": "t1"})
    assert art and art.kind == "conversation_thread" and f.store.owners_of(art.artifact_id) == {rahul}
    assert {t.metadata.get("dpdp_principal_id") for t in saver.list(None)} == {rahul}


def test_context_can_come_from_configurable_and_its_absence_is_refused(workdir):
    tmp, _ = workdir
    f, saver = _fw(tmp), InMemorySaver()
    rahul, _ = _people(f)
    agent = _agent(f, saver)
    agent.invoke({"messages": [{"role": "user", "content": "rahul@example.in"}]},
                 {"configurable": {"thread_id": "t2", "dpdp_principal_id": rahul, "dpdp_purpose": "service"}})
    assert "rahul@example.in" not in _saver_text(saver)
    with pytest.raises(MissingContext):
        _agent(f, InMemorySaver()).invoke({"messages": [{"role": "user", "content": "hi"}]},
                                          {"configurable": {"thread_id": "t3"}})


def test_consent_is_checked_before_the_model_is_called(workdir):
    tmp, _ = workdir
    f = _fw(tmp)
    stranger = f.principal("no-consent")
    agent = _agent(f, InMemorySaver())
    with f.context(stranger, "service"), pytest.raises(ConsentDenied):
        agent.invoke({"messages": [{"role": "user", "content": "rahul@example.in"}]},
                     {"configurable": {"thread_id": "t4"}})
    assert SpyModel.seen == []


def test_the_checkpointer_alone_still_keeps_raw_values_out_of_storage(workdir):
    tmp, _ = workdir
    f, saver = _fw(tmp), InMemorySaver()
    rahul, _ = _people(f)
    with f.context(rahul, "service"):
        _agent(f, saver, middleware=False).invoke({"messages": [{"role": "user", "content": "9876543210"}]},
                                                  {"configurable": {"thread_id": "t5"}})
    assert "9876543210" not in _saver_text(saver)


def test_erasure_deletes_owned_threads_and_keeps_threads_that_only_mention(workdir):
    tmp, _ = workdir
    saver = InMemorySaver()
    conn = LangGraphCheckpointConnector("langgraph_checkpoints", checkpointer=saver)
    f = _fw(tmp, langgraph_checkpoints=conn)
    rahul, priya = _people(f)
    f.grant_consent(priya, "service")
    with f.context(rahul, "service"):
        _agent(f, saver).invoke({"messages": [{"role": "user", "content": "nominee priya@example.in"}]},
                                {"configurable": {"thread_id": "rahul-1"}})
    with f.context(priya, "service"):
        _agent(f, saver).invoke({"messages": [{"role": "user", "content": "my number 9123456780"}]},
                                {"configurable": {"thread_id": "priya-1"}})
    res = f.erase(priya)
    assert res["status"] == "completed", res
    threads = {str(t.config["configurable"]["thread_id"]) for t in saver.list(None)}
    assert threads == {"rahul-1"}                                   # Rahul's conversation survives
    assert all(v["ok"] for v in res["verification"]), res["verification"]
    plan = {p["artifact_id"]: p["action"] for p in res["plan"] if p["store"] == "langgraph_checkpoints"}
    owned = f.store.find_artifact("langgraph_checkpoints", {"thread_id": "priya-1"}).artifact_id
    mentioned = f.store.find_artifact("langgraph_checkpoints", {"thread_id": "rahul-1"}).artifact_id
    assert plan == {owned: "delete", mentioned: "redact"}
    done = {a["artifact_id"]: a for a in f.store.actions_for(res["request_id"])}
    assert "only mentions" in json.dumps(done[mentioned], default=str)
    with f.context(rahul, "service"):
        state = saver.get_tuple({"configurable": {"thread_id": "rahul-1"}}).checkpoint["channel_values"]
        shown = f.reveal(json.dumps(state["messages"][0].content))
        assert "priya@example.in" not in shown and "[ERASED]" in shown        # not a bare token either


def test_concurrent_writes_to_one_thread_register_it_once(workdir):
    from concurrent.futures import ThreadPoolExecutor
    tmp, _ = workdir
    f = _fw(tmp)
    rahul, _ = _people(f)

    def touch(i):
        with f.context(rahul, "service"):
            f.touch_artifact("conversation_thread", "langgraph_checkpoints", {"thread_id": "busy"})
    with ThreadPoolExecutor(8) as ex:
        list(ex.map(touch, range(32)))
    assert len(f.store.artifacts_in_stores(["langgraph_checkpoints"])) == 1


def test_native_discovery_finds_owned_threads_nobody_registered(workdir):
    tmp, _ = workdir
    saver = InMemorySaver()
    conn = LangGraphCheckpointConnector("langgraph_checkpoints", checkpointer=saver)
    f = _fw(tmp, langgraph_checkpoints=conn)
    rahul, _ = _people(f)
    with f.context(rahul, "service"):
        _agent(f, saver).invoke({"messages": [{"role": "user", "content": "hello"}]},
                                {"configurable": {"thread_id": "lost"}})
    art = f.store.find_artifact("langgraph_checkpoints", {"thread_id": "lost"})
    f.store.set_artifact_status(art.artifact_id, "erased")           # lineage forgot about it
    from dpdp_rights.connectors.base import ErasureContext
    found = conn.discover(ErasureContext(rahul, f.vault.tokens_for(rahul)))
    assert [(d.locator["thread_id"], d.note) for d in found] == [("lost", "owned")]


def test_connector_from_config_factory(workdir, monkeypatch):
    import sys
    import types
    mod = types.ModuleType("my_memory")
    mod.saver = InMemorySaver()
    monkeypatch.setitem(sys.modules, "my_memory", mod)
    c = LangGraphCheckpointConnector("lg", factory="my_memory:saver")
    assert c.cp is mod.saver
    with pytest.raises(ValueError, match="module:attribute"):
        LangGraphCheckpointConnector("lg", factory="nonsense")


# ==== OpenAI Agents SDK =======================================================================================
pytest.importorskip("agents")
from agents import Agent, Runner, SQLiteSession  # noqa: E402
from agents.items import ModelResponse  # noqa: E402
from agents.models.interface import Model  # noqa: E402
from agents.usage import Usage  # noqa: E402
from openai.types.responses import ResponseOutputMessage, ResponseOutputText  # noqa: E402

from dpdp_rights.connectors.frameworks import AgentsSessionConnector  # noqa: E402
from dpdp_rights.integrations import openai_agents as oa  # noqa: E402


class FakeModel(Model):
    def __init__(self, reply="noted"):
        self.reply, self.seen = reply, []

    async def get_response(self, system_instructions, input, model_settings, tools, output_schema, handoffs,
                           tracing, **kw):
        self.seen.append(json.dumps(input, default=str))
        msg = ResponseOutputMessage(id="m1", type="message", role="assistant", status="completed",
                                    content=[ResponseOutputText(type="output_text", text=self.reply, annotations=[])])
        return ModelResponse(output=[msg], usage=Usage(), response_id=None)

    def stream_response(self, *a, **k):
        raise NotImplementedError


def test_agents_model_input_and_session_hold_tokens_only(workdir):
    tmp, _ = workdir
    f = _fw(tmp)
    rahul, _ = _people(f)
    model, inner = FakeModel("We will call 9123456780"), SQLiteSession("s1", str(tmp / "s.db"))
    sess = oa.ProtectedSession(inner, f, principal_id=rahul, purpose="service")
    agent = Agent(name="a", instructions="help", model=model)

    async def go():
        with f.context(rahul, "service"):
            await Runner.run(agent, "rahul@example.in and 9876543210", session=sess, run_config=oa.run_config(f))
            await Runner.run(agent, "and again", session=sess, run_config=oa.run_config(f))
        return await inner.get_items()

    items = asyncio.run(go())
    assert not any(v in json.dumps(model.seen) for v in RAW)        # second call includes the history
    assert not any(v in json.dumps(items) for v in RAW) and len(items) == 4
    art = f.store.find_artifact("openai_agents_sessions", {"session_id": "s1"})
    assert art and f.store.owners_of(art.artifact_id) == {rahul}
    assert oa.run_config(f).trace_include_sensitive_data is False


def test_agents_filter_reads_the_run_context_and_refuses_without_one(workdir):
    tmp, _ = workdir
    f = _fw(tmp)
    rahul, _ = _people(f)
    model = FakeModel()
    agent = Agent(name="a", instructions="help", model=model)
    asyncio.run(Runner.run(agent, "9876543210", context={"dpdp_principal_id": rahul, "dpdp_purpose": "service"},
                           run_config=oa.run_config(f)))
    assert "9876543210" not in model.seen[0]
    with pytest.raises(oa.MissingContext):
        asyncio.run(Runner.run(agent, "hi", run_config=oa.run_config(f)))
    stranger = f.principal("nobody")
    with pytest.raises(ConsentDenied):
        asyncio.run(Runner.run(agent, "9876543210", context={"dpdp_principal_id": stranger, "dpdp_purpose": "service"},
                               run_config=oa.run_config(f)))


def test_agents_session_erasure_clears_owned_sessions_and_verifies(workdir):
    tmp, _ = workdir
    db = str(tmp / "sessions.db")
    conn = AgentsSessionConnector("openai_agents_sessions", session_factory=lambda sid: SQLiteSession(sid, db))
    f = _fw(tmp, openai_agents_sessions=conn)
    rahul, priya = _people(f)
    f.grant_consent(priya, "service")
    agent = Agent(name="a", instructions="help", model=FakeModel())

    async def chat(pid, sid, text):
        s = oa.ProtectedSession(SQLiteSession(sid, db), f, principal_id=pid, purpose="service")
        with f.context(pid, "service"):
            await Runner.run(agent, text, session=s, run_config=oa.run_config(f))

    asyncio.run(chat(rahul, "rahul-s", "my nominee is priya@example.in"))
    asyncio.run(chat(priya, "priya-s", "call me on 9123456780"))
    res = f.erase(priya)
    assert res["status"] == "completed", res
    assert all(v["ok"] for v in res["verification"]), res["verification"]
    assert asyncio.run(SQLiteSession("priya-s", db).get_items()) == []
    assert len(asyncio.run(SQLiteSession("rahul-s", db).get_items())) == 2
    assert sorted(p["action"] for p in res["plan"] if p["store"] == "openai_agents_sessions") == ["delete", "redact"]


def test_capability_matrix_lists_the_new_connectors():
    from dpdp_rights.connectors.base import connector_class
    for name, disc in (("langgraph_checkpoints", "native"), ("openai_agents_sessions", "lineage")):
        caps = connector_class(name).capabilities
        assert caps.discover == disc and caps.deletion == "container"
