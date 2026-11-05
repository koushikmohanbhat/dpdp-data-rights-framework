"""Example: an Amazon Bedrock AgentCore Runtime agent instrumented with the framework.

Deploy with the AgentCore starter toolkit (`agentcore configure && agentcore launch`).
The caller passes the DPDP context either as W3C baggage or in the payload:

    {"prompt": "...", "dpdp": {"principal_id": "dp_...", "purpose": "service_delivery", "session_id": "s-1"}}

Requires: pip install bedrock-agentcore dpdp-data-rights-framework[aws]
"""
import logging
import os

from bedrock_agentcore.runtime import BedrockAgentCoreApp  # type: ignore

from dpdp_rights import DataRightsFramework
from dpdp_rights.core import context as dpdp_ctx
from dpdp_rights.integrations.agentcore import AgentCoreMemory, envelope_from_agentcore_payload

dpdp = DataRightsFramework.from_yaml(os.environ.get("DPDP_CONFIG", "config/dpdp.aws.yaml"))
memory = AgentCoreMemory(dpdp, memory_id=os.environ["AGENTCORE_MEMORY_ID"], connector_name="agentcore_memory")

logging.basicConfig(level=logging.INFO)
for h in logging.getLogger().handlers:
    h.addFilter(dpdp.logging_filter())       # runtime logs -> CloudWatch carry tokens only

app = BedrockAgentCoreApp()
SYSTEM = os.environ.get("AGENT_SYSTEM_PROMPT", "You are an insurance onboarding agent. Never ask for full Aadhaar numbers.")


@app.entrypoint
def invoke(payload, context=None):
    env = envelope_from_agentcore_payload(payload, getattr(context, "request_headers", None))
    tok = dpdp_ctx.set_current(env)
    try:
        turn = memory.add_turn(payload["prompt"], role="USER")             # tokenised + lineage
        answer = dpdp.generate(turn["text"], system=SYSTEM, already_protected=True)
        memory.add_turn(answer.text, role="ASSISTANT", parents=[turn["artifact_id"]])
        logging.info("answered session=%s", env.session_id)
        return {"result": answer.reveal()}                                 # detokenised for the owner only
    finally:
        dpdp_ctx.reset(tok)


if __name__ == "__main__":
    app.run()
