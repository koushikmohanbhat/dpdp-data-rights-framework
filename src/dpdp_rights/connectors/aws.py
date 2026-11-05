"""AWS-native connectors.

* aws_cloudwatch_logs   - CloudWatch Logs incl. Bedrock model-invocation logs,
                          AgentCore Runtime logs and AgentCore Observability spans (aws/spans)
* aws_agentcore_memory  - Amazon Bedrock AgentCore Memory (short-term events + long-term records)
* aws_bedrock_kb        - Amazon Bedrock Knowledge Bases documents
* aws_s3_objects        - S3 objects, including all versions in versioned buckets
* aws_dynamodb          - DynamoDB items keyed by principal (chat history, profiles)
"""
from __future__ import annotations

import re
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from ..core.models import Action
from .base import Connector, Discovered, ErasureContext, VerifyResult, register


def _boto(service: str, region: str | None, client=None):
    if client is not None:
        return client
    import boto3

    return boto3.client(service, region_name=region)


# ---------------------------------------------------------------------------
@register("aws_cloudwatch_logs")
class CloudWatchLogsConnector(Connector):
    """Discovers which log streams mention a principal using CloudWatch Logs Insights.

    CloudWatch log events cannot be deleted individually, so the default action
    is CRYPTO_SHRED (logs carry tokens only, thanks to the framework's logging filter
    and tokenised prompts). If ``delete_streams: true`` and streams are
    dedicated per session/principal, matching streams are deleted.

    Verification runs an Insights query for every raw value (held in memory
    only) to prove no plaintext PII leaked into logs before tokenisation.

    Options: log_group_names (list), region, lookback_days (default 30),
             delete_streams (bool), require_retention_days (int, flags groups without retention),
             apply_retention_days (int, optionally sets retention on groups with none)
    """

    supports = {Action.CRYPTO_SHRED, Action.DELETE}

    def __init__(self, name: str, log_group_names: list[str], region: str | None = None,
                 lookback_days: int = 30, delete_streams: bool = False,
                 require_retention_days: int | None = 90, apply_retention_days: int | None = None,
                 client=None, poll_seconds: float = 1.0, **kw):
        super().__init__(name, **kw)
        self.logs = _boto("logs", region, client)
        self.groups = log_group_names
        self.lookback = lookback_days
        self.delete_streams = delete_streams
        self.require_retention = require_retention_days
        self.apply_retention = apply_retention_days
        self.poll = poll_seconds

    def _query(self, needles: list[str]) -> list[dict[str, str]]:
        if not needles:
            return []
        rx = "|".join(re.escape(n).replace("/", "\\/") for n in needles)
        qs = f"fields @log, @logStream | filter @message like /{rx}/ | stats count(*) as hits by @log, @logStream"
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=self.lookback)
        qid = self.logs.start_query(logGroupNames=self.groups, startTime=int(start.timestamp()),
                                    endTime=int(end.timestamp()), queryString=qs, limit=10000)["queryId"]
        while True:
            r = self.logs.get_query_results(queryId=qid)
            if r["status"] in ("Complete", "Failed", "Cancelled", "Timeout"):
                break
            time.sleep(self.poll)
        if r["status"] != "Complete":
            raise RuntimeError(f"Logs Insights query {qid} ended with {r['status']}")
        return [{f["field"]: f["value"] for f in row} for row in r.get("results", [])]

    @staticmethod
    def _group_name(log_field: str) -> str:
        # @log is "<accountId>:<logGroupName>"
        return log_field.split(":", 1)[1] if ":" in log_field else log_field

    def discover(self, ctx: ErasureContext) -> list[Discovered]:
        rows = self._query(ctx.needles)
        return [Discovered("log", {"logGroupName": self._group_name(r["@log"]), "logStreamName": r["@logStream"]},
                           note=f"{r.get('hits')} matching events") for r in rows]

    def retention_report(self) -> list[dict[str, Any]]:
        out = []
        for g in self.groups:
            resp = self.logs.describe_log_groups(logGroupNamePrefix=g)
            for lg in resp.get("logGroups", []):
                if lg["logGroupName"] != g:
                    continue
                days = lg.get("retentionInDays")
                if days is None and self.apply_retention:
                    self.logs.put_retention_policy(logGroupName=g, retentionInDays=self.apply_retention)
                    days = self.apply_retention
                ok = days is not None and (self.require_retention is None or days <= self.require_retention)
                out.append({"logGroupName": g, "retentionInDays": days, "within_policy": ok,
                            "data_protection_policy": bool(lg.get("dataProtectionStatus"))})
        return out

    def _delete(self, artifact, ctx, fallback_from=None):
        if not self.delete_streams:
            return self._crypto_shred(artifact, ctx)
        self.logs.delete_log_stream(logGroupName=artifact.locator["logGroupName"],
                                    logStreamName=artifact.locator["logStreamName"])
        return self._ok(artifact, Action.DELETE, deleted_stream=artifact.locator["logStreamName"])

    def _crypto_shred(self, artifact, ctx):
        res = super()._crypto_shred(artifact, ctx)
        res.detail["note"] += " CloudWatch events are immutable; they age out under the group's retention policy."
        return res

    def verify(self, ctx: ErasureContext) -> VerifyResult:
        raw = sorted({v for v in ctx.probes.values() if v and len(v) >= 4})
        hits = self._query(raw) if raw else []
        retention = self.retention_report()
        bad_ret = [r for r in retention if not r["within_policy"]]
        findings = [{"raw_value_in_stream": h} for h in hits] + [{"retention_issue": r} for r in bad_ret]
        return VerifyResult(self.name, not hits, findings,
                            note="Tokens may remain in immutable events; they are unreadable post-shred.")


# ---------------------------------------------------------------------------
@register("aws_agentcore_memory")
class AgentCoreMemoryConnector(Connector):
    """Amazon Bedrock AgentCore Memory.

    Convention: the agent uses the framework's pseudonymous principal id as the
    AgentCore ``actorId`` (see integrations.agentcore). Then discovery is
    exact: ListSessions(actorId) -> ListEvents, and ListMemoryRecords for each
    namespace template (e.g. "/users/{actorId}/preferences").

    Events and records are immutable, so REDACT falls back to DELETE.
    Options: memory_id, region, namespaces (list of templates with {actorId})
    """

    supports = {Action.DELETE}

    def __init__(self, name: str, memory_id: str, region: str | None = None,
                 namespaces: list[str] | None = None, client=None, **kw):
        super().__init__(name, **kw)
        self.client = _boto("bedrock-agentcore", region, client)
        self.memory_id = memory_id
        self.namespaces = namespaces or ["/users/{actorId}"]

    def _paginate(self, op: str, key: str, **kw) -> list[dict]:
        out, token = [], None
        while True:
            args = dict(kw, **({"nextToken": token} if token else {}))
            r = getattr(self.client, op)(**args)
            out += r.get(key, [])
            token = r.get("nextToken")
            if not token:
                return out

    def discover(self, ctx: ErasureContext) -> list[Discovered]:
        actor = ctx.principal_id
        found: list[Discovered] = []
        for s in self._paginate("list_sessions", "sessionSummaries", memoryId=self.memory_id, actorId=actor):
            sid = s["sessionId"]
            for e in self._paginate("list_events", "events", memoryId=self.memory_id, sessionId=sid,
                                    actorId=actor, includePayloads=False):
                found.append(Discovered("memory_event", {"memoryId": self.memory_id, "actorId": actor,
                                                         "sessionId": sid, "eventId": e["eventId"]}))
        for tmpl in self.namespaces:
            ns = tmpl.format(actorId=actor)
            for rec in self._paginate("list_memory_records", "memoryRecordSummaries",
                                      memoryId=self.memory_id, namespace=ns):
                found.append(Discovered("memory_record", {"memoryId": self.memory_id, "namespace": ns,
                                                          "memoryRecordId": rec["memoryRecordId"]}))
        return found

    def _delete(self, artifact, ctx, fallback_from=None):
        loc = artifact.locator
        if "eventId" in loc:
            self.client.delete_event(memoryId=loc["memoryId"], sessionId=loc["sessionId"],
                                     eventId=loc["eventId"], actorId=loc["actorId"])
            what = {"eventId": loc["eventId"]}
        else:
            args = {"memoryId": loc["memoryId"], "memoryRecordId": loc["memoryRecordId"]}
            if loc.get("namespace"):
                args["namespace"] = loc["namespace"]
            self.client.delete_memory_record(**args)
            what = {"memoryRecordId": loc["memoryRecordId"]}
        if fallback_from:
            what["fallback_from"] = fallback_from.value
        return self._ok(artifact, Action.DELETE, **what)


# ---------------------------------------------------------------------------
@register("aws_bedrock_kb")
class BedrockKnowledgeBaseConnector(Connector):
    """Amazon Bedrock Knowledge Bases.

    mode=direct     -> DeleteKnowledgeBaseDocuments (S3 or CUSTOM data sources)
    mode=s3_resync  -> delete the S3 object(s) then StartIngestionJob to drop vectors
    Locator: {"s3_uri": "s3://bucket/key"} or {"custom_id": "..."}
    """

    supports = {Action.DELETE}

    def __init__(self, name: str, knowledge_base_id: str, data_source_id: str, region: str | None = None,
                 mode: str = "direct", client=None, s3_client=None, **kw):
        super().__init__(name, **kw)
        self.agent = _boto("bedrock-agent", region, client)
        self.s3 = s3_client
        self.region = region
        self.kb, self.ds, self.mode = knowledge_base_id, data_source_id, mode

    def _ident(self, loc: dict) -> dict:
        if "custom_id" in loc:
            return {"dataSourceType": "CUSTOM", "custom": {"id": loc["custom_id"]}}
        return {"dataSourceType": "S3", "s3": {"uri": loc["s3_uri"]}}

    def _delete(self, artifact, ctx, fallback_from=None):
        loc = artifact.locator
        if self.mode == "direct":
            r = self.agent.delete_knowledge_base_documents(knowledgeBaseId=self.kb, dataSourceId=self.ds,
                                                           documentIdentifiers=[self._ident(loc)])
            return self._ok(artifact, Action.DELETE, status=[d.get("status") for d in r.get("documentDetails", [])])
        s3 = _boto("s3", self.region, self.s3)
        bucket, key = loc["s3_uri"][5:].split("/", 1)
        s3.delete_object(Bucket=bucket, Key=key)
        job = self.agent.start_ingestion_job(knowledgeBaseId=self.kb, dataSourceId=self.ds,
                                             description="dpdp erasure resync")
        return self._ok(artifact, Action.DELETE, ingestion_job=job["ingestionJob"]["ingestionJobId"])

    def verify(self, ctx):
        return VerifyResult(self.name, True, [], note="Verified per-artifact via action status; KB has no principal index.")


# ---------------------------------------------------------------------------
@register("aws_s3_objects")
class S3ObjectsConnector(Connector):
    """S3 objects. Deletes every version when ``purge_versions`` (default true),
    otherwise a delete marker would leave the data recoverable.
    Options: bucket, prefix_template (e.g. "transcripts/{principal_id}/"), region"""

    supports = {Action.DELETE}

    def __init__(self, name: str, bucket: str, prefix_template: str | None = None, region: str | None = None,
                 purge_versions: bool = True, client=None, **kw):
        super().__init__(name, **kw)
        self.s3 = _boto("s3", region, client)
        self.bucket, self.prefix_tmpl, self.purge = bucket, prefix_template, purge_versions

    def discover(self, ctx):
        if not self.prefix_tmpl:
            return []
        prefix = self.prefix_tmpl.format(principal_id=ctx.principal_id)
        out = []
        for page in self.s3.get_paginator("list_objects_v2").paginate(Bucket=self.bucket, Prefix=prefix):
            out += [Discovered("record", {"bucket": self.bucket, "key": o["Key"]}) for o in page.get("Contents", [])]
        return out

    def _delete(self, artifact, ctx, fallback_from=None):
        b, k = artifact.locator["bucket"], artifact.locator["key"]
        deleted = 0
        if self.purge:
            for page in self.s3.get_paginator("list_object_versions").paginate(Bucket=b, Prefix=k):
                for v in page.get("Versions", []) + page.get("DeleteMarkers", []):
                    if v["Key"] == k:
                        self.s3.delete_object(Bucket=b, Key=k, VersionId=v["VersionId"])
                        deleted += 1
        if deleted == 0:
            self.s3.delete_object(Bucket=b, Key=k)
            deleted = 1
        return self._ok(artifact, Action.DELETE, versions_deleted=deleted)


# ---------------------------------------------------------------------------
@register("aws_dynamodb")
class DynamoDBConnector(Connector):
    """Items whose partition key is the principal id (chat history, user profiles, agent state).
    Options: table, partition_key, sort_key?, region"""

    supports = {Action.DELETE}

    def __init__(self, name: str, table: str, partition_key: str, sort_key: str | None = None,
                 region: str | None = None, resource=None, **kw):
        super().__init__(name, **kw)
        import boto3

        self.table = (resource or boto3.resource("dynamodb", region_name=region)).Table(table)
        self.pk, self.sk = partition_key, sort_key

    def discover(self, ctx):
        from boto3.dynamodb.conditions import Key

        out, kwargs = [], {"KeyConditionExpression": Key(self.pk).eq(ctx.principal_id)}
        while True:
            r = self.table.query(**kwargs)
            for it in r.get("Items", []):
                key = {self.pk: it[self.pk], **({self.sk: it[self.sk]} if self.sk else {})}
                out.append(Discovered("record", {"key": key}))
            if "LastEvaluatedKey" not in r:
                return out
            kwargs["ExclusiveStartKey"] = r["LastEvaluatedKey"]

    def _delete(self, artifact, ctx, fallback_from=None):
        self.table.delete_item(Key=artifact.locator["key"])
        return self._ok(artifact, Action.DELETE)
