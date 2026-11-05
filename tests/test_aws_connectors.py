"""AWS connectors against botocore Stubber (no AWS account needed)."""
import boto3
import pytest
from botocore.stub import ANY, Stubber

from dpdp_erasure.connectors.aws import AgentCoreMemoryConnector, CloudWatchLogsConnector
from dpdp_erasure.connectors.base import ErasureContext
from dpdp_erasure.core.models import Action, Artifact

MEM = "support_mem-abcdefghij"


@pytest.fixture
def agentcore():
    client = boto3.client("bedrock-agentcore", region_name="ap-south-1",
                          aws_access_key_id="x", aws_secret_access_key="y")
    return client, Stubber(client)


def test_agentcore_discover_and_delete(agentcore):
    client, st = agentcore
    pid = "dp_0123456789abcdef0123"
    st.add_response("list_sessions", {"sessionSummaries": [{"sessionId": "s1", "actorId": pid,
                                                             "createdAt": "2026-11-01T00:00:00Z"}]},
                    {"memoryId": MEM, "actorId": pid})
    st.add_response("list_events", {"events": [{"memoryId": MEM, "actorId": pid, "sessionId": "s1",
                                                "eventId": "1#abc", "eventTimestamp": "2026-11-01T00:00:00Z",
                                                "payload": []}]},
                    {"memoryId": MEM, "sessionId": "s1", "actorId": pid, "includePayloads": False})
    st.add_response("list_memory_records", {"memoryRecordSummaries": [{
        "memoryRecordId": "mem-rec-1234567890abcdefghij1234567890abcd", "content": {"text": "prefers phone"},
        "memoryStrategyId": "strat", "namespaces": [f"/users/{pid}"], "createdAt": "2026-11-01T00:00:00Z"}]},
        {"memoryId": MEM, "namespace": f"/users/{pid}"})
    st.add_response("delete_event", {"eventId": "1#abc"},
                    {"memoryId": MEM, "sessionId": "s1", "eventId": "1#abc", "actorId": pid})
    st.add_response("delete_memory_record", {"memoryRecordId": "mem-rec-1234567890abcdefghij1234567890abcd"},
                    {"memoryId": MEM, "memoryRecordId": "mem-rec-1234567890abcdefghij1234567890abcd", "namespace": f"/users/{pid}"})
    with st:
        conn = AgentCoreMemoryConnector("agentcore_memory", memory_id=MEM, client=client)
        ctx = ErasureContext(pid, [])
        found = conn.discover(ctx)
        assert [d.kind for d in found] == ["memory_event", "memory_record"]
        for d in found:
            r = conn.erase(Artifact("a", d.kind, "agentcore_memory", d.locator), Action.REDACT, ctx)
            assert r.ok and r.action == "delete" and r.detail["fallback_from"] == "redact"
    st.assert_no_pending_responses()


def test_cloudwatch_discover_and_verify():
    client = boto3.client("logs", region_name="ap-south-1", aws_access_key_id="x", aws_secret_access_key="y")
    st = Stubber(client)
    q = {"logGroupNames": ["aws/spans"], "startTime": ANY, "endTime": ANY, "queryString": ANY, "limit": 10000}
    st.add_response("start_query", {"queryId": "q1"}, q)
    st.add_response("get_query_results", {"status": "Complete", "results": [[
        {"field": "@log", "value": "123456789012:aws/spans"}, {"field": "@logStream", "value": "default"},
        {"field": "hits", "value": "4"}]]}, {"queryId": "q1"})
    # verify: raw-value query returns nothing; retention is configured
    st.add_response("start_query", {"queryId": "q2"}, q)
    st.add_response("get_query_results", {"status": "Complete", "results": []}, {"queryId": "q2"})
    st.add_response("describe_log_groups", {"logGroups": [{"logGroupName": "aws/spans", "retentionInDays": 30}]},
                    {"logGroupNamePrefix": "aws/spans"})
    with st:
        conn = CloudWatchLogsConnector("cw", log_group_names=["aws/spans"], client=client, poll_seconds=0)
        ctx = ErasureContext("dp_x", ["<EMAIL_aaaaaaaaaaaa>"], {"<EMAIL_aaaaaaaaaaaa>": "a@x.in"})
        found = conn.discover(ctx)
        assert found[0].locator == {"logGroupName": "aws/spans", "logStreamName": "default"}
        r = conn.erase(Artifact("a", "log", "cw", found[0].locator), Action.DELETE, ctx)
        assert r.ok and r.action == "crypto_shred"          # delete_streams disabled -> shred
        v = conn.verify(ctx)
        assert v.ok and not v.findings
    st.assert_no_pending_responses()
