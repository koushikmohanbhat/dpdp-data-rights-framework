"""Built-in connectors run the same conformance kit that plug-in connectors must pass.

SQL, JSONL and log files run locally; Redis uses fakeredis; S3 and DynamoDB use moto (in-memory AWS).
Cloud connectors are also covered by the live suite in tests/integration.
"""
import json
import sqlite3

import pytest

from dpdp_rights.connectors.local import JsonlDatasetConnector, LogFileConnector, RedisCacheConnector, SqlTableConnector
from dpdp_rights.testing.conformance import ConnectorConformance, ConnectorHarness


# ---- SQL table ------------------------------------------------------------------------------------------
class SqlHarness(ConnectorHarness):
    def __init__(self, tmp_path):
        self.db = tmp_path / "app.db"
        con = sqlite3.connect(self.db)
        con.execute("CREATE TABLE notes (id TEXT PRIMARY KEY, principal_id TEXT, body TEXT)")
        con.commit()

    def connector(self):
        return SqlTableConnector("sut", f"sqlite:///{self.db}", "notes", principal_column="principal_id",
                                 content_column="body")

    def write(self, record_id, content, principal_id):
        with sqlite3.connect(self.db) as con:
            con.execute("INSERT INTO notes VALUES (?, ?, ?)", (record_id, principal_id, content))
        return {"id": record_id}

    def read(self, locator):
        with sqlite3.connect(self.db) as con:
            row = con.execute("SELECT body FROM notes WHERE id=?", (locator["id"],)).fetchone()
        return row[0] if row else None


class TestSqlTableConformance(ConnectorConformance):
    def make_harness(self, tmp_path):
        return SqlHarness(tmp_path)


# ---- JSONL dataset --------------------------------------------------------------------------------------
class JsonlHarness(ConnectorHarness):
    kind = "eval_row"

    def __init__(self, tmp_path):
        self.path = tmp_path / "golden.jsonl"
        self.path.write_text("")

    def connector(self):
        return JsonlDatasetConnector("sut", str(self.path))

    def write(self, record_id, content, principal_id):
        with self.path.open("a") as f:
            f.write(json.dumps({"id": record_id, "input": content}) + "\n")
        return {"id": record_id}

    def read(self, locator):
        for line in self.path.read_text().splitlines():
            row = json.loads(line)
            if row["id"] == locator["id"]:
                return row["input"]
        return None


class TestJsonlDatasetConformance(ConnectorConformance):
    def make_harness(self, tmp_path):
        return JsonlHarness(tmp_path)


# ---- log file (immutable: crypto-shred only) ------------------------------------------------------------
class LogHarness(ConnectorHarness):
    kind = "log"

    def __init__(self, tmp_path):
        self.path = tmp_path / "app.log"
        self.path.write_text("")

    def connector(self):
        return LogFileConnector("sut", str(self.path))

    def write(self, record_id, content, principal_id):
        with self.path.open("a") as f:
            f.write(f"{record_id} {content}\n")
        return {"path": str(self.path), "line": record_id}

    def read(self, locator):
        for line in self.path.read_text().splitlines():
            if line.startswith(locator["line"] + " "):
                return line.split(" ", 1)[1]
        return None


class TestLogFileConformance(ConnectorConformance):
    def make_harness(self, tmp_path):
        return LogHarness(tmp_path)


# ---- Redis cache ----------------------------------------------------------------------------------------
class RedisHarness(ConnectorHarness):
    kind = "cache_entry"
    accepts_raw_text = False

    def __init__(self):
        fakeredis = pytest.importorskip("fakeredis")
        self.r = fakeredis.FakeRedis()

    def connector(self):
        return RedisCacheConnector("sut", client=self.r)

    def write(self, record_id, content, principal_id):
        key = f"cache:{record_id}"
        self.r.set(key, content)
        self.r.sadd("dpdp:idx:" + principal_id, key)      # what DataRightsFramework.track_cache_key does
        return {"key": key}

    def read(self, locator):
        v = self.r.get(locator["key"])
        return v.decode() if v is not None else None


class TestRedisCacheConformance(ConnectorConformance):
    def make_harness(self, tmp_path):
        return RedisHarness()


# ---- S3 and DynamoDB (moto) -----------------------------------------------------------------------------
@pytest.fixture
def aws(monkeypatch):
    moto = pytest.importorskip("moto")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "ap-south-1")
    for k in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"):
        monkeypatch.setenv(k, "testing")
    with moto.mock_aws():
        yield


class S3Harness(ConnectorHarness):
    accepts_raw_text = False         # S3 connector verifies by re-discovery, not content scans

    def __init__(self):
        import boto3

        self.s3 = boto3.client("s3", region_name="ap-south-1")
        self.s3.create_bucket(Bucket="conf", CreateBucketConfiguration={"LocationConstraint": "ap-south-1"})
        self.s3.put_bucket_versioning(Bucket="conf", VersioningConfiguration={"Status": "Enabled"})

    def connector(self):
        from dpdp_rights.connectors.aws import S3ObjectsConnector

        return S3ObjectsConnector("sut", "conf", prefix_template="transcripts/{principal_id}/", client=self.s3)

    def write(self, record_id, content, principal_id):
        key = f"transcripts/{principal_id}/{record_id}.txt"
        self.s3.put_object(Bucket="conf", Key=key, Body=content.encode())
        return {"bucket": "conf", "key": key}

    def read(self, locator):
        vs = self.s3.list_object_versions(Bucket="conf", Prefix=locator["key"])
        if not vs.get("Versions"):
            return None                     # every version gone, not just hidden by a delete marker
        try:
            return self.s3.get_object(Bucket="conf", Key=locator["key"])["Body"].read().decode()
        except self.s3.exceptions.NoSuchKey:
            return "<only older versions remain>"


@pytest.mark.usefixtures("aws")
class TestS3Conformance(ConnectorConformance):
    def make_harness(self, tmp_path):
        return S3Harness()


class DynamoHarness(ConnectorHarness):
    accepts_raw_text = False

    def __init__(self):
        import boto3

        self.ddb = boto3.resource("dynamodb", region_name="ap-south-1")
        self.table = self.ddb.create_table(
            TableName="chat", BillingMode="PAY_PER_REQUEST",
            KeySchema=[{"AttributeName": "principal_id", "KeyType": "HASH"},
                       {"AttributeName": "ts", "KeyType": "RANGE"}],
            AttributeDefinitions=[{"AttributeName": "principal_id", "AttributeType": "S"},
                                  {"AttributeName": "ts", "AttributeType": "S"}])

    def connector(self):
        from dpdp_rights.connectors.aws import DynamoDBConnector

        return DynamoDBConnector("sut", "chat", "principal_id", sort_key="ts", resource=self.ddb)

    def write(self, record_id, content, principal_id):
        self.table.put_item(Item={"principal_id": principal_id, "ts": record_id, "text": content})
        return {"key": {"principal_id": principal_id, "ts": record_id}}

    def read(self, locator):
        it = self.table.get_item(Key=locator["key"]).get("Item")
        return it["text"] if it else None


@pytest.mark.usefixtures("aws")
class TestDynamoDBConformance(ConnectorConformance):
    def make_harness(self, tmp_path):
        return DynamoHarness()
