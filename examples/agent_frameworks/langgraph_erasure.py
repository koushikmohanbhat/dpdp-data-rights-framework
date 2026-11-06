"""Offline: a LangGraph agent whose model and memory only ever see tokens, then erasure of one person.

    pip install -e ".[langchain]"
    python examples/agent_frameworks/langgraph_erasure.py

Uses a fake chat model and an in-memory checkpointer, so it needs no API key. See docs/agent-frameworks.md.
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

from langchain.agents import create_agent
from langchain_core.language_models.fake_chat_models import FakeMessagesListChatModel
from langchain_core.messages import AIMessage
from langgraph.checkpoint.memory import InMemorySaver

from dpdp_rights import DataRightsFramework
from dpdp_rights.connectors.frameworks import LangGraphCheckpointConnector
from dpdp_rights.core.config import FrameworkConfig
from dpdp_rights.integrations.langchain import DPDPMiddleware, ProtectedCheckpointer

RAW = ("rahul@example.in", "9876543210", "priya@example.in", "9123456780")


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="dpdp-lg-"))
    dpdp = DataRightsFramework(FrameworkConfig.model_validate({
        "environment": "dev",
        "vault": {"local_master_key_path": str(tmp / "master.key")},
        "lineage": {"url": f"sqlite:///{tmp}/lineage.db"},
        "certificates": {"signer": "local", "local_key_path": str(tmp / "sign.key")},
        "purposes": [{"id": "support", "description": "Answer the customer's questions"}],
    }), connectors={})
    saver = InMemorySaver()
    dpdp.connectors["langgraph_checkpoints"] = LangGraphCheckpointConnector("langgraph_checkpoints",
                                                                            checkpointer=saver)
    checkpointer = ProtectedCheckpointer(saver, dpdp)

    rahul, priya = dpdp.principal("cust-rahul"), dpdp.principal("cust-priya")
    for p in (rahul, priya):
        dpdp.grant_consent(p, "support")
    dpdp.register_identifier(priya, "EMAIL", "priya@example.in")

    def agent(reply):
        return create_agent(FakeMessagesListChatModel(responses=[AIMessage(content=reply)]), tools=[],
                            middleware=[DPDPMiddleware(dpdp)], checkpointer=checkpointer)

    def chat(pid, thread, text, reply):
        with dpdp.context(pid, "support"):
            out = agent(reply).invoke({"messages": [{"role": "user", "content": text}]},
                                      {"configurable": {"thread_id": thread}})
            print(f"  [{thread}] user:  {text}")
            print(f"  [{thread}] model saw: {out['messages'][0].content}")
            print(f"  [{thread}] shown to the user: {dpdp.reveal(out['messages'][-1].content)}")

    print("1. Two conversations. Rahul names Priya as his nominee.")
    chat(rahul, "rahul-1", "I'm Rahul, rahul@example.in, 9876543210. Nominee: priya@example.in",
         "Thanks Rahul, we'll call 9876543210.")
    chat(priya, "priya-1", "Please call me on 9123456780", "Sure, calling 9123456780 shortly.")

    stored = repr(saver.storage) + repr(saver.writes) + repr(saver.blobs)
    print(f"\n2. Raw values anywhere in the checkpointer: {any(v in stored for v in RAW)}")

    print("\n3. Priya asks to be erased.")
    res = dpdp.erase(priya)
    for p in res["plan"]:
        if p["store"] == "langgraph_checkpoints":
            thread = dpdp.store.get_artifact(p["artifact_id"]).locator["thread_id"]
            print(f"  {thread}: {p['action']} ({p['reason']})")
    threads = sorted({t.config["configurable"]["thread_id"] for t in saver.list(None)})
    print(f"  threads left: {threads}; verification ok: {all(v['ok'] for v in res['verification'])}")
    with dpdp.context(rahul, "support"):
        first = saver.get_tuple({"configurable": {"thread_id": "rahul-1"}}).checkpoint["channel_values"]
        print(f"  Rahul's thread now reads: {dpdp.reveal(json.dumps(first['messages'][0].content))}")
    ok = (res["status"] == "completed" and threads == ["rahul-1"] and not any(v in stored for v in RAW)
          and "[ERASED]" in dpdp.vault.reveal(json.dumps(first["messages"][0].content), {rahul}))
    print("\nOK" if ok else "\nUNEXPECTED RESULT")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
