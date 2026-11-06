# Agent frameworks: LangChain / LangGraph and the OpenAI Agents SDK

Without an integration, an agent team has to remember `dpdp.protect()` before every model call and
`dpdp.track_artifact()` for every place a conversation is saved. Agent frameworks make that easy to miss, because
the framework itself sends messages to the model and saves conversation memory. These integrations hook into
both points, so a team adds them once.

| | LangChain / LangGraph | OpenAI Agents SDK |
|---|---|---|
| Install | `pip install "dpdp-data-rights-framework[langchain]"` | `pip install "dpdp-data-rights-framework[openai-agents]"` |
| Before every model call | `DPDPMiddleware`: tokenises human, tool and system messages in the agent state, checks consent | `protect_model_input`: a `call_model_input_filter` that tokenises every input item, checks consent |
| After the model replies | Tokenises raw personal data the model produced | The stored copy is tokenised by the session; `final_output` is the model's text (see below) |
| Conversation memory | `ProtectedCheckpointer` wraps any checkpointer: every checkpoint and pending write is tokenised at save time; owner recorded in checkpoint metadata | `ProtectedSession` wraps any `Session` (SQLite, SQLAlchemy, Redis, OpenAI Conversations): stored items are tokenised |
| Lineage | Each thread is registered once (`conversation_thread`) and linked to every person whose data enters it | Each session is registered once (`agent_session`) and linked the same way |
| Erasure connector | `langgraph_checkpoints`: native discovery (lists checkpoints), deletes owned threads, verifies by rescan | `openai_agents_sessions`: lineage only (sessions cannot be listed), clears owned sessions, verifies by re-reading them |

**Try it offline:** `python examples/agent_frameworks/langgraph_erasure.py` runs two conversations (one naming
the other person as a nominee), shows the model seeing only tokens, then erases one person: their thread is
deleted and the other thread keeps the mention as `[ERASED]`. CI runs it.

Tested with langchain 1.5, langgraph 1.2, langgraph-checkpoint 4.3 and openai-agents 0.25, using fake models (no
API calls).

## Who the data is about

Every call needs a Data Principal and a purpose. The integrations take, in order:

1. the active `with dpdp.context(principal_id, purpose):` block, or
2. `dpdp_principal_id` and `dpdp_purpose` in the run context (Agents SDK `context=`, LangChain `context=`) or in
   LangGraph's `configurable`.

With neither, they **refuse**: the middleware and the input filter raise `MissingContext` before the model is
called, and the checkpointer refuses to save rather than store raw text. A purpose without consent raises
`ConsentDenied`, also before the model is called.

## LangChain / LangGraph

```python
from langchain.agents import create_agent
from langgraph.checkpoint.postgres import PostgresSaver
from dpdp_rights.integrations.langchain import DPDPMiddleware, ProtectedCheckpointer

checkpointer = ProtectedCheckpointer(PostgresSaver.from_conn_string(DB_URL), dpdp)
agent = create_agent(model, tools=tools, middleware=[DPDPMiddleware(dpdp)], checkpointer=checkpointer)

with dpdp.context(pid, "policy_issuance"):
    out = agent.invoke({"messages": [{"role": "user", "content": user_text}]},
                       {"configurable": {"thread_id": f"{pid}:{session}"}})
    reply = dpdp.reveal(out["messages"][-1].content)     # detokenise only to show this person
```

**Why both pieces.** LangGraph saves the user's input in a checkpoint before any middleware runs, and a
checkpointer keeps every checkpoint of a thread. With the middleware alone, the raw input would stay in thread
history. With the checkpointer alone, storage is clean but the model would receive raw text and consent would not
be checked. Use both. A hand-built `StateGraph` (no `create_agent`) gets the storage protection from the
checkpointer; call `dpdp.protect()` in the node that calls the model.

Register the connector so erasure reaches the threads (in code, or from config with a factory):

```python
from dpdp_rights.connectors.frameworks import LangGraphCheckpointConnector
dpdp.connectors["langgraph_checkpoints"] = LangGraphCheckpointConnector("langgraph_checkpoints",
                                                                        checkpointer=checkpointer)
```

```yaml
connectors:
  - name: langgraph_checkpoints
    type: langgraph_checkpoints
    options: {factory: "myapp.memory:checkpointer", scan_limit: 20000}
```

## OpenAI Agents SDK

```python
from agents import Agent, Runner, SQLiteSession
from dpdp_rights.integrations.openai_agents import ProtectedSession, run_config

session = ProtectedSession(SQLiteSession(f"{pid}:{conv}", "memory.db"), dpdp, principal_id=pid,
                           purpose="policy_issuance")
with dpdp.context(pid, "policy_issuance"):
    result = await Runner.run(agent, user_text, session=session, run_config=run_config(dpdp))
    reply = dpdp.reveal(result.final_output)
```

`run_config(dpdp)` sets the input filter and turns `trace_include_sensitive_data` off. The SDK's own tracing
records run inputs and tool outputs *before* any filter runs, so with sensitive data on, raw values would reach
the tracing backend. Keep it off, or point tracing at a store you register and can erase.

```python
from dpdp_rights.connectors.frameworks import AgentsSessionConnector
dpdp.connectors["openai_agents_sessions"] = AgentsSessionConnector(
    "openai_agents_sessions", session_factory=lambda sid: SQLiteSession(sid, "memory.db"))
```

**`final_output`** is the model's text as returned. Anything it contains that came from the conversation is a
token (reveal it for display). If the model writes a *new* raw value, the stored session copy is tokenised, but
the string your code receives is not: run `dpdp.protect()` on it before you store or log it anywhere else.

## Erasure

| The thread or session | What happens | Why |
|---|---|---|
| Belongs to the person | Deleted: every checkpoint and pending write (`delete_thread`), or the session cleared (`clear_session`) | Their own conversation |
| Only mentions them (a nominee named in someone else's conversation) | Kept; recorded as crypto-shredded | It holds their tokens only, which become unreadable when their key is destroyed; deleting would erase another person's conversation |
| Holds their raw values (written without the wrappers) | Found by the LangGraph connector's scan and deleted | Safety net; not available for Agents SDK sessions, which cannot be listed |

Verification lists checkpoints again (LangGraph) or re-opens each cleared session (Agents SDK).

## Limits

- **Tool arguments.** Tools receive tokens. A tool that needs a real value (send an email, look up a policy)
  should call `dpdp.reveal(value)` inside the tool, under the same context, so the value exists only there.
- **Tool outputs** are tokenised before the *next* model call and before storage; the tool's own logs are yours
  to route through the logging filter.
- **Framework tracing** (LangSmith, the Agents SDK trace processor) records what it receives before these hooks.
  Configure it to omit inputs and outputs, or treat it as a store with its own connector.
- The LangGraph scan reads up to `scan_limit` checkpoints; above that, discovery relies on lineage.
- Streaming and LangGraph Platform's hosted store are not covered yet; neither are LlamaIndex, CrewAI, Strands or
  Google ADK ([roadmap](roadmap.md)).
