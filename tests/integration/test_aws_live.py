"""Live integration tests against a real AWS account.

Skipped unless DPDP_IT_AWS=1. All resource IDs come from SSM Parameter Store
(``DPDP_IT_SSM_PREFIX``, default ``/dpdp-it``), written by deploy/terraform/aws-integration.
No account-specific values live in this repository. See docs/testing.md.

Optional environment:
  AWS_REGION                    region of the test stack
  BEDROCK_CHAT_MODEL_ID         enables the Bedrock Converse test
  BEDROCK_EMBEDDING_MODEL_ID    enables the embeddings test
  DPDP_IT_LINEAGE_URL           PostgreSQL URL for the control plane (default: SQLite in a temp dir)
  OPENAI_API_KEY + OPENAI_TEST_MODEL       enables the OpenAI stored-response test
  ANTHROPIC_API_KEY                         enables the Anthropic Files API test
"""
from __future__ import annotations

import json
import os
import secrets
import time
import uuid
from datetime import datetime, timezone

import pytest

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(os.environ.get("DPDP_IT_AWS") != "1", reason="set DPDP_IT_AWS=1 to run live AWS tests"),
]

RUN = uuid.uuid4().hex[:10]


def poll(fn, timeout: float = 300, interval: float = 10, desc: str = "condition"):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        last = fn()
        if last:
            return last
        time.sleep(interval)
    raise AssertionError(f"timed out after {timeout}s waiting for {desc}; last={last!r}")


# ---- fixtures ------------------------------------------------------------------------------
@pytest.fixture(scope="session")
def boto():
    import boto3

    return boto3.session.Session(region_name=os.environ.get("AWS_REGION"))


@pytest.fixture(scope="session")
def params(boto):
    prefix = os.environ.get("DPDP_IT_SSM_PREFIX", "/dpdp-it").rstrip("/")
    ssm = boto.client("ssm")
    out, kw = {}, {"Path": prefix, "Recursive": True}
    while True:
        r = ssm.get_parameters_by_path(**kw)
        out.update({p["Name"].rsplit("/", 1)[-1]: p["Value"] for p in r["Parameters"]})
        if not r.get("NextToken"):
            break
        kw["NextToken"] = r["NextToken"]
    missing = {"vault_kms_key_arn", "sealed_kms_key_arn", "signing_key_arn", "break_glass_role", "vault_table_prefix",
               "chat_history_table", "data_bucket", "cert_bucket", "log_group", "cognito_user_pool"} - out.keys()
    assert not missing, f"SSM parameters missing under {prefix}: {missing} (apply deploy/terraform/aws-integration)"
    return out


@pytest.fixture
def lineage_url(tmp_path):
    return os.environ.get("DPDP_IT_LINEAGE_URL") or f"sqlite:///{tmp_path}/lineage.db"


def make_framework(params, lineage_url, tmp_path, connectors=(), **extra):
    from dpdp_rights import DataRightsFramework, FrameworkConfig

    region = params["region"]
    cfg = {
        "provider": {"type": "echo"},
        "pii": {"detectors": ["regex"]},
        "vault": {"key_wrapper": "aws_kms", "kms_key_id": params["vault_kms_key_arn"], "storage": "dynamodb",
                  "dynamodb_table_prefix": params["vault_table_prefix"], "region": region,
                  "sealed_key_wrapper": "aws_kms", "sealed_kms_key_id": params["sealed_kms_key_arn"],
                  "sealed_role_arn": params["break_glass_role"]},
        "lineage": {"url": lineage_url},
        "purposes": [{"id": "service_delivery"}, {"id": "marketing"}],
        "connectors": list(connectors),
        "certificates": {"signer": "aws_kms", "key_id": params["signing_key_arn"], "archive": "s3",
                         "archive_uri": f"s3://{params['cert_bucket']}/it-{RUN}", "archive_mode": "GOVERNANCE",
                         "retain_days": 1, "region": region},
    }
    cfg.update(extra)
    return DataRightsFramework(FrameworkConfig.from_dict(cfg))


# ---- vault, keys, break-glass ---------------------------------------------------------------------
def test_kms_vault_dynamodb_sealed_key_and_break_glass(params, lineage_url, tmp_path, boto):
    from botocore.exceptions import ClientError

    fw = make_framework(params, lineage_url, tmp_path)
    pid = fw.principal(f"it-vault-{RUN}")
    tok = fw.vault.tokenize(pid, "EMAIL", f"vault-{RUN}@example.in")
    assert fw.vault.detokenize(tok) == f"vault-{RUN}@example.in"

    fw.vault.shred(pid, escrow=True)
    assert fw.vault.detokenize(tok) is None                       # app reads blocked
    escrow = f"escrow_{pid}"
    wrapped = fw.vault.storage.get_key(escrow)
    with pytest.raises(ClientError):                              # the test role itself cannot decrypt sealed keys
        boto.client("kms").decrypt(CiphertextBlob=wrapped, EncryptionContext={"dpdp:principal": escrow})
    assert fw.vault.detokenize(tok, privileged=True) == f"vault-{RUN}@example.in"   # via break-glass role
    fw.vault.destroy(escrow)
    assert fw.vault.detokenize(tok, privileged=True) is None


def test_comprehend_detects_names(params):
    from dpdp_rights.pii.detectors import ComprehendDetector

    ents = ComprehendDetector(region=params["region"], min_score=0.5).detect(
        "Hello, my name is Asha Nair and my email is asha.nair@example.in")
    assert {"NAME", "EMAIL"} <= {e.type for e in ents}


# ---- models ---------------------------------------------------------------------------------------------
@pytest.mark.skipif(not os.environ.get("BEDROCK_CHAT_MODEL_ID"), reason="BEDROCK_CHAT_MODEL_ID not set")
def test_bedrock_converse(params):
    from dpdp_rights.providers.bedrock_provider import BedrockProvider

    p = BedrockProvider(os.environ["BEDROCK_CHAT_MODEL_ID"], region=params["region"])
    r = p.generate("Reply with the single word: ok", system="You are terse.", maxTokens=1024)  # room for reasoning models
    assert r.text.strip()


@pytest.mark.skipif(not os.environ.get("BEDROCK_EMBEDDING_MODEL_ID"), reason="BEDROCK_EMBEDDING_MODEL_ID not set")
def test_bedrock_embeddings(params):
    from dpdp_rights.providers.bedrock_provider import BedrockProvider

    p = BedrockProvider("unused", embedding_model=os.environ["BEDROCK_EMBEDDING_MODEL_ID"], region=params["region"])
    vec = p.embed(["<EMAIL_aaaaaaaaaaaa> asked about a refund"])[0]
    assert len(vec) >= 256


# ---- AgentCore -----------------------------------------------------------------------------------------
@pytest.fixture(scope="module")
def agentcore_memory(params, boto):
    ctl = boto.client("bedrock-agentcore-control")
    mem = ctl.create_memory(name=f"dpdpit{RUN}", eventExpiryDuration=7,
                            description="dpdp-rights integration test (auto-deleted)")["memory"]
    mid = mem["id"]
    try:
        poll(lambda: ctl.get_memory(memoryId=mid)["memory"]["status"] == "ACTIVE", timeout=600, interval=15,
             desc="AgentCore memory ACTIVE")
        yield mid
    finally:
        ctl.delete_memory(memoryId=mid)


def test_agentcore_memory_events_are_found_and_deleted(params, lineage_url, tmp_path, agentcore_memory, boto):
    from dpdp_rights.integrations.agentcore import AgentCoreMemory

    region = params["region"]
    fw = make_framework(params, lineage_url, tmp_path, connectors=[
        {"name": "agentcore_memory", "type": "aws_agentcore_memory",
         "options": {"memory_id": agentcore_memory, "region": region, "namespaces": []}}])
    pid = fw.principal(f"it-mem-{RUN}")
    fw.grant_consent(pid, "service_delivery")
    mem = AgentCoreMemory(fw, agentcore_memory, region=region)
    with fw.context(pid, purpose="service_delivery", session_id=f"s{RUN}"):
        t = mem.add_turn(f"My email is mem-{RUN}@example.in, please update my policy", role="USER")
        mem.add_turn("Done, I have updated it.", role="ASSISTANT", parents=[t["artifact_id"]])
    assert "@example.in" not in t["text"]                          # only tokens reach AgentCore

    conn = fw.connectors["agentcore_memory"]
    from dpdp_rights.connectors.base import ErasureContext

    ctx = ErasureContext(pid, fw.vault.tokens_for(pid))
    poll(lambda: len(conn.discover(ctx)) >= 2, timeout=120, interval=5, desc="memory events listed")
    res = fw.erase(pid)
    assert res["status"] in ("completed", "completed_with_exceptions"), res
    assert res["actions"].get("delete", 0) >= 2
    poll(lambda: not conn.discover(ctx), timeout=120, interval=5, desc="memory events deleted")


def test_agentcore_identity_revocation_via_cognito(params, boto):
    from dpdp_rights.connectors.agents import AgentCoreIdentityConnector
    from dpdp_rights.connectors.base import ErasureContext
    from dpdp_rights.core.models import Action, Artifact

    idp = boto.client("cognito-idp")
    pool, user = params["cognito_user_pool"], f"dp_it{RUN}"
    idp.admin_create_user(UserPoolId=pool, Username=user, MessageAction="SUPPRESS")
    try:
        c = AgentCoreIdentityConnector("identity", cognito_user_pool_id=pool, region=params["region"])
        d = c.discover(ErasureContext(user, []))[0]
        r = c.erase(Artifact("a", d.kind, "identity", d.locator), Action.DELETE, ErasureContext(user, []))
        assert r.ok and r.detail["revoked_via"] == ["cognito_global_sign_out"]
    finally:
        idp.admin_delete_user(UserPoolId=pool, Username=user)


# ---- logs and traces ------------------------------------------------------------------------------------
def test_cloudwatch_logs_insights_discovery_and_raw_leak_detection(params, boto):
    from dpdp_rights.connectors.aws import CloudWatchLogsConnector
    from dpdp_rights.connectors.base import ErasureContext

    logs, lg = boto.client("logs"), params["log_group"]
    stream, pid, tok, raw = f"it-{RUN}", f"dp_it{RUN}", f"<PHONE_IN_{RUN}ab>", "9876501234"
    logs.create_log_stream(logGroupName=lg, logStreamName=stream)
    now = int(time.time() * 1000)
    logs.put_log_events(logGroupName=lg, logStreamName=stream, logEvents=[
        {"timestamp": now, "message": f"principal={pid} callback requested for {tok}"},
        {"timestamp": now + 1, "message": f"legacy-dialer called {raw}"}])            # simulated leak
    c = CloudWatchLogsConnector("cw", log_group_names=[lg], region=params["region"], lookback_days=1, poll_seconds=2)
    ctx = ErasureContext(pid, [tok], {tok: raw})
    found = poll(lambda: c.discover(ctx), timeout=600, interval=20, desc="Logs Insights to index the stream")
    assert found[0].locator["logStreamName"] == stream
    v = c.verify(ctx)
    assert not v.ok and v.findings                                  # the raw phone number is caught


def test_xray_annotation_discovery(params, boto):
    from dpdp_rights.connectors.base import ErasureContext
    from dpdp_rights.connectors.observability import XRayConnector

    xr, pid = boto.client("xray"), f"dp_it{RUN}"
    t = time.time()
    trace_id = f"1-{int(t):08x}-{secrets.token_hex(12)}"
    seg = {"name": "dpdp-it", "id": secrets.token_hex(8), "trace_id": trace_id, "start_time": t, "end_time": t + 0.05,
           "annotations": {"dpdp_principal": pid}, "metadata": {"default": {"prompt": "<EMAIL_aaaaaaaaaaaa> asked"}}}
    assert not xr.put_trace_segments(TraceSegmentDocuments=[json.dumps(seg)]).get("UnprocessedTraceSegments")
    c = XRayConnector("xray", region=params["region"], lookback_hours=1)
    ctx = ErasureContext(pid, ["<EMAIL_aaaaaaaaaaaa>"], {"<EMAIL_aaaaaaaaaaaa>": "x@example.in"})
    found = poll(lambda: c.discover(ctx), timeout=300, interval=15, desc="X-Ray to index the trace")
    assert trace_id in found[0].locator["trace_ids"]
    assert c.verify(ctx).ok


# ---- data stores --------------------------------------------------------------------------------------------
def test_s3_versioned_objects_fully_purged(params, boto):
    from dpdp_rights.connectors.aws import S3ObjectsConnector
    from dpdp_rights.connectors.base import ErasureContext
    from dpdp_rights.core.models import Action, Artifact

    s3, bucket, pid = boto.client("s3"), params["data_bucket"], f"dp_it{RUN}"
    key = f"it/{pid}/transcript.txt"
    s3.put_object(Bucket=bucket, Key=key, Body=b"v1 <EMAIL_aaaaaaaaaaaa>")
    s3.put_object(Bucket=bucket, Key=key, Body=b"v2 <EMAIL_aaaaaaaaaaaa>")
    c = S3ObjectsConnector("s3", bucket=bucket, prefix_template="it/{principal_id}/", region=params["region"])
    ctx = ErasureContext(pid, [])
    d = c.discover(ctx)
    assert [x.locator["key"] for x in d] == [key]
    r = c.erase(Artifact("a", "record", "s3", d[0].locator), Action.DELETE, ctx)
    assert r.ok and r.detail["versions_deleted"] >= 2
    left = s3.list_object_versions(Bucket=bucket, Prefix=key)
    assert not left.get("Versions") and not left.get("DeleteMarkers")


def test_dynamodb_chat_history(params, boto):
    from dpdp_rights.connectors.aws import DynamoDBConnector
    from dpdp_rights.connectors.base import ErasureContext
    from dpdp_rights.core.models import Action, Artifact

    table, pid = params["chat_history_table"], f"dp_it{RUN}"
    t = boto.resource("dynamodb").Table(table)
    for i in range(2):
        t.put_item(Item={"principal_id": pid, "ts": f"2026-11-06T00:00:0{i}Z", "text": "<EMAIL_aaaaaaaaaaaa>"})
    c = DynamoDBConnector("chat", table=table, partition_key="principal_id", sort_key="ts", region=params["region"])
    ctx = ErasureContext(pid, [])
    found = c.discover(ctx)
    assert len(found) == 2
    for d in found:
        assert c.erase(Artifact("a", "record", "chat", d.locator), Action.DELETE, ctx).ok
    assert c.discover(ctx) == []


def test_jsonl_eval_set_on_s3(params, boto):
    from dpdp_rights.connectors.base import ErasureContext
    from dpdp_rights.connectors.local import JsonlDatasetConnector
    from dpdp_rights.core.models import Action, Artifact

    s3, bucket, pid, tok = boto.client("s3"), params["data_bucket"], f"dp_it{RUN}", f"<EMAIL_{RUN}ab>"
    key = f"it/{RUN}/evals.jsonl"
    rows = [{"id": "e1", "input": f"refund for {tok}"}, {"id": "e2", "input": "generic question"}]
    s3.put_object(Bucket=bucket, Key=key, Body="".join(json.dumps(r) + "\n" for r in rows).encode())
    try:
        c = JsonlDatasetConnector("evals", path=f"s3://{bucket}/{key}")
        ctx = ErasureContext(pid, [tok])
        d = c.discover(ctx)
        assert [x.locator["id"] for x in d] == ["e1"]
        assert c.erase(Artifact("a", "eval_row", "evals", d[0].locator), Action.DELETE, ctx).ok
        body = s3.get_object(Bucket=bucket, Key=key)["Body"].read().decode()
        assert tok not in body and "e2" in body
    finally:
        for v in s3.list_object_versions(Bucket=bucket, Prefix=key).get("Versions", []):
            s3.delete_object(Bucket=bucket, Key=key, VersionId=v["VersionId"])


# ---- end to end: API -> queue -> worker -> signed certificate in Object Lock -------------------------------
def test_end_to_end_signed_certificate_in_object_lock(params, lineage_url, tmp_path, boto):
    from fastapi.testclient import TestClient

    from dpdp_rights.api.app import create_app
    from dpdp_rights.security.auth import hash_api_key

    region, bucket, table = params["region"], params["data_bucket"], params["chat_history_table"]
    key = secrets.token_urlsafe(24)
    fw = make_framework(params, lineage_url, tmp_path, connectors=[
        {"name": "transcripts", "type": "aws_s3_objects",
         "options": {"bucket": bucket, "prefix_template": "e2e/{principal_id}/", "region": region}},
        {"name": "chat", "type": "aws_dynamodb",
         "options": {"table": table, "partition_key": "principal_id", "sort_key": "ts", "region": region}}],
        api={"auth": {"mode": "api_key", "api_keys": [
            {"name": "backend", "sha256": hash_api_key(key), "roles": ["service"]},
            {"name": "dpo", "sha256": hash_api_key(key + "-dpo"), "roles": ["dpo"]}]}})
    api = TestClient(create_app(fw))
    h = {"x-api-key": key}
    ext = f"it-e2e-{RUN}"
    pid = api.post("/v1/consents", json={"external_id": ext, "purpose_id": "service_delivery"}, headers=h).json()["principal_id"]

    with fw.context(pid, purpose="service_delivery", session_id=f"e2e{RUN}"):
        safe = fw.protect(f"My name is Ravi Kumar, phone 98765 43210, email e2e-{RUN}@example.in")
        s3 = boto.client("s3")
        s3.put_object(Bucket=bucket, Key=f"e2e/{pid}/t1.txt", Body=safe.text.encode())
        fw.track_artifact("record", "transcripts", {"bucket": bucket, "key": f"e2e/{pid}/t1.txt"},
                          content=safe.text, element_ids=safe.element_ids)
        boto.resource("dynamodb").Table(table).put_item(Item={"principal_id": pid, "ts": "t1", "text": safe.text})
        fw.track_artifact("record", "chat", {"key": {"principal_id": pid, "ts": "t1"}}, content=safe.text)

    r = api.post("/v1/erasure-requests", headers=h | {"Idempotency-Key": f"e2e-{RUN}"},
                 json={"external_id": ext, "verified_by": "integration-test", "verification_ref": RUN})
    assert r.status_code == 202, r.text
    rid = r.json()["request_id"]
    jobs = fw.process_jobs()
    assert jobs and jobs[0]["ok"], jobs
    assert jobs[0]["result"]["status"] == "completed", fw.store.actions_for(rid)

    v = api.get(f"/v1/erasure-requests/{rid}/certificate/verify", headers={"x-api-key": key + "-dpo"}).json()
    assert v["hash_ok"] and v["chain_ok"] and v["signature_ok"], v
    arch_bucket, arch_key = v["archive_uri"].removeprefix("s3://").split("/", 1)
    head = s3.head_object(Bucket=arch_bucket, Key=arch_key)
    assert head["ObjectLockMode"] == "GOVERNANCE"
    assert not s3.list_object_versions(Bucket=bucket, Prefix=f"e2e/{pid}/").get("Versions")
    # clean up the governance-locked test certificate
    for ver in s3.list_object_versions(Bucket=arch_bucket, Prefix=arch_key).get("Versions", []):
        s3.delete_object(Bucket=arch_bucket, Key=arch_key, VersionId=ver["VersionId"], BypassGovernanceRetention=True)
    fw.vault.destroy(f"escrow_{pid}")


# ---- optional provider-side state -------------------------------------------------------------------------------
@pytest.mark.skipif(not (os.environ.get("OPENAI_API_KEY") and os.environ.get("OPENAI_TEST_MODEL")),
                    reason="OPENAI_API_KEY and OPENAI_TEST_MODEL not set")
def test_openai_stored_response_deleted():
    import openai

    from dpdp_rights.connectors.base import ErasureContext
    from dpdp_rights.connectors.openai_platform import OpenAIPlatformConnector
    from dpdp_rights.core.models import Action, Artifact
    from dpdp_rights.providers.openai_provider import OpenAIProvider

    p = OpenAIProvider(os.environ["OPENAI_TEST_MODEL"], store=True)
    res = p.generate("Reply with ok. Ref <EMAIL_aaaaaaaaaaaa>")
    rid = res.provider_ref["response_id"]
    c = OpenAIPlatformConnector("openai_platform")
    assert c.erase(Artifact("a", "provider_response", "openai_platform", res.provider_ref), Action.DELETE,
                   ErasureContext("dp_x", [])).ok
    with pytest.raises(openai.NotFoundError):
        openai.OpenAI().responses.retrieve(rid)


@pytest.mark.skipif(not os.environ.get("ANTHROPIC_API_KEY"), reason="ANTHROPIC_API_KEY not set")
def test_anthropic_file_deleted():
    import anthropic

    from dpdp_rights.connectors.anthropic_platform import FILES_BETA, AnthropicPlatformConnector
    from dpdp_rights.connectors.base import ErasureContext
    from dpdp_rights.core.models import Action, Artifact

    client = anthropic.Anthropic()
    f = client.beta.files.upload(file=("it.txt", f"run {RUN} <EMAIL_aaaaaaaaaaaa>".encode(), "text/plain"),
                                 betas=[FILES_BETA])
    c = AnthropicPlatformConnector("anthropic_platform", client=client)
    assert c.erase(Artifact("a", "provider_file", "anthropic_platform", {"type": "file", "file_id": f.id}),
                   Action.DELETE, ErasureContext("dp_x", [])).ok
    with pytest.raises(anthropic.NotFoundError):
        client.beta.files.retrieve_metadata(f.id, betas=[FILES_BETA])


def test_report_run_id():
    print(f"integration run id: {RUN} at {datetime.now(timezone.utc).isoformat()}")
