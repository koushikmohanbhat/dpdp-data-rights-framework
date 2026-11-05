"""Example: an Amazon Bedrock AgentCore Runtime agent instrumented with the kit.

Deploy with the AgentCore starter toolkit (`agentcore configure && agentcore launch`).
The caller passes the DPDP context either as W3C baggage or in the payload:

    {"prompt": "...", "dpdp": {"principal_id": "dp_...", "purpose": "support_resolution", "session_id": "s-1"}}

Requires: pip install bedrock-agentcore genai-dpdp-erasure-kit[aws]
"""
import logging
import os

from bedrock_agentcore.runtime import BedrockAgentCoreApp  # type: ignore

from dpdp_erasure import ErasureKit
from dpdp_erasure.core import context as dpdp_ctx
from dpdp_erasure.integrations.agentcore import AgentCoreMemory, envelope_from_agentcore_payload

kit = ErasureKit.from_yaml(os.environ.get("DPDP_CONFIG", "config/dpdp.aws.yaml"))
memory = AgentCoreMemory(kit, memory_id=os.environ["AGENTCORE_MEMORY_ID"], connector_name="agentcore_memory")

logging.basicConfig(level=logging.INFO)
for h in logging.getLogger().handlers:
    h.addFilter(kit.logging_filter())       # runtime logs -> CloudWatch carry tokens only

app = BedrockAgentCoreApp()
SYSTEM = "You are a support agent for an Indian bank. Never ask for full Aadhaar numbers."


@app.entrypoint
def invoke(payload, context=None):
    env = envelope_from_agentcore_payload(payload, getattr(context, "request_headers", None))
    tok = dpdp_ctx.set_current(env)
    try:
        turn = memory.add_turn(payload["prompt"], role="USER")             # tokenised + lineage
        answer = kit.generate(turn["text"], system=SYSTEM, already_protected=True)
        memory.add_turn(answer.text, role="ASSISTANT", parents=[turn["artifact_id"]])
        logging.info("answered session=%s", env.session_id)
        return {"result": answer.reveal()}                                 # detokenised for the owner only
    finally:
        dpdp_ctx.reset(tok)


if __name__ == "__main__":
    app.run()
