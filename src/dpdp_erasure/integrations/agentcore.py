"""Amazon Bedrock AgentCore integration.

* ``AgentCoreMemory`` - writes tokenised conversation turns to AgentCore Memory
  using the pseudonymous principal id as ``actorId`` and registers each event
  in lineage, so the ``aws_agentcore_memory`` connector can erase it exactly.
* ``envelope_from_agentcore_payload`` - rebuild the DPDP context inside an
  AgentCore Runtime entrypoint from the invocation payload / headers.
* AgentCore Observability (OTel spans -> CloudWatch ``aws/spans`` and runtime
  log groups) is covered by the ``aws_cloudwatch_logs`` connector; because the
  agent only handles tokenised text, spans contain tokens, not PII.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from ..core import context as ctxmod
from ..core.context import ContextEnvelope
from ..core.models import EdgeType


class AgentCoreMemory:
    def __init__(self, kit, memory_id: str, connector_name: str = "agentcore_memory",
                 region: str | None = None, client=None):
        if client is None:
            import boto3

            client = boto3.client("bedrock-agentcore", region_name=region)
        self.kit, self.client, self.memory_id, self.store = kit, client, memory_id, connector_name

    def add_turn(self, text: str, role: str = "USER", session_id: str | None = None,
                 parents: list[str] | None = None) -> dict[str, Any]:
        env = ctxmod.require()
        safe = self.kit.protect(text) if role == "USER" else None
        payload_text = safe.text if safe else self.kit.tokenizer.tokenize(text, env.principal_id).text
        sid = session_id or env.session_id or "default"
        r = self.client.create_event(
            memoryId=self.memory_id, actorId=env.principal_id, sessionId=sid,
            eventTimestamp=datetime.now(timezone.utc),
            payload=[{"conversational": {"content": {"text": payload_text}, "role": role}}],
            metadata={"dpdp_purpose": {"stringValue": env.purpose_id}},
        )
        ev = r["event"]
        art = self.kit.track_artifact(
            "memory_event", self.store,
            {"memoryId": self.memory_id, "actorId": env.principal_id, "sessionId": sid, "eventId": ev["eventId"]},
            content=payload_text, element_ids=safe.element_ids if safe else (),
            parents=parents or [], edge_type=EdgeType.COPY,
        )
        return {"event_id": ev["eventId"], "artifact_id": art.artifact_id, "text": payload_text}


def envelope_from_agentcore_payload(payload: dict[str, Any], headers: dict[str, str] | None = None) -> ContextEnvelope:
    """In an AgentCore Runtime @app.entrypoint: prefer W3C baggage, fall back to payload fields."""
    if headers:
        env = ContextEnvelope.from_headers(headers)
        if env:
            return env
    d = payload.get("dpdp", {})
    return ContextEnvelope(d["principal_id"], d["purpose"], d.get("session_id"), tuple(d.get("parents", [])))
