"""Providers receive tokens only; provider-side state is registered for erasure."""
from types import SimpleNamespace

import boto3
from botocore.stub import ANY, Stubber

from dpdp_rights import DataRightsFramework
from dpdp_rights.connectors.openai_platform import OpenAIPlatformConnector
from dpdp_rights.providers.bedrock_provider import BedrockProvider
from dpdp_rights.providers.openai_provider import OpenAIProvider


class FakeResponses:
    def __init__(self):
        self.sent, self.deleted = [], []

    def create(self, **kw):
        self.sent.append(kw)
        return SimpleNamespace(id="resp_123", output_text="Refund raised for " + kw["input"].split()[-1], usage=None)

    def delete(self, rid):
        self.deleted.append(rid)


def test_openai_provider_sees_tokens_and_stored_response_is_erased(dpdp):
    fake = SimpleNamespace(responses=FakeResponses(), files=None)
    dpdp.provider = OpenAIProvider("gpt-test", store=True, client=fake)
    dpdp.connectors["openai_platform"] = OpenAIPlatformConnector("openai_platform", client=fake)
    dpdp.orchestrator.connectors = dpdp.connectors
    pid = dpdp.principal("o-1")
    dpdp.grant_consent(pid, "service")
    with dpdp.context(pid, purpose="service"):
        ans = dpdp.generate("please refund o1@x.in")
    sent = fake.responses.sent[0]
    assert "o1@x.in" not in sent["input"] and "<EMAIL_" in sent["input"] and sent["store"] is True
    with dpdp.context(pid, purpose="service"):
        assert ans.reveal().endswith("o1@x.in")
    res = dpdp.erase(pid)
    assert fake.responses.deleted == ["resp_123"] and res["status"] == "completed"


def test_bedrock_converse_with_tokens(workdir):
    client = boto3.client("bedrock-runtime", region_name="ap-south-1", aws_access_key_id="x", aws_secret_access_key="y")
    st = Stubber(client)
    st.add_response("converse", {
        "output": {"message": {"role": "assistant", "content": [{"text": "ok"}]}},
        "stopReason": "end_turn", "usage": {"inputTokens": 5, "outputTokens": 1, "totalTokens": 6},
        "metrics": {"latencyMs": 10}},
        {"modelId": "m", "messages": ANY, "system": [{"text": "sys"}]})
    with st:
        r = BedrockProvider("m", client=client).generate("<EMAIL_aaaaaaaaaaaa> wants a refund", system="sys")
    assert r.text == "ok" and r.provider_ref is None
    assert isinstance(DataRightsFramework, type)
