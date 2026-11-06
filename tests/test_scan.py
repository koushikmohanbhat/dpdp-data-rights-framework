"""Read-only discovery scan (docs/scan.md): exported files, configured stores, the draft inventory, the CLI."""
import gzip
import hashlib
import json
from pathlib import Path

import pytest

from dpdp_rights import scan as sc
from dpdp_rights.connectors.base import Connector, Sample
from dpdp_rights.core.config import PIIConfig
from dpdp_rights.pii.detectors import build_detector

DET = build_detector(PIIConfig())
RAW = {"phone": "9876543210", "aadhaar": "2345 6789 0124", "email": "asha.k@example.in",
       "card": "4111 1111 1111 1111", "upi": "asha@okhdfcbank"}


def _no_values(rep):
    text = json.dumps(rep, default=str)
    return not any(v in text for v in RAW.values())


# ---- exported files -----------------------------------------------------------------------------------------------
def _exports(tmp: Path) -> Path:
    d = tmp / "exports"
    d.mkdir()
    (d / "cw.json").write_text(json.dumps({"events": [
        {"message": f"user phone {RAW['phone']}"}, {"message": f"my aadhaar is {RAW['aadhaar']}"},
        {"message": "email <EMAIL_3f9a1c0b7d2e> confirmed"}, {"message": "cache miss"}]}))
    with gzip.open(d / "app.log.gz", "wt") as f:
        f.write("".join(f"req {i} ok\n" for i in range(30)) + f"card {RAW['card']} upi {RAW['upi']}\n")
    (d / "chats.jsonl").write_text(json.dumps({"text": f"mail me at {RAW['email']}"}) + "\n" + json.dumps("hi") + "\n")
    (d / "crm.csv").write_text(f"id,note\n1,call {RAW['phone']}\n2,no data\n")
    (d / "list.json").write_text(json.dumps([{"q": "hello"}, {"q": f"phone {RAW['phone']}"}]))
    (d / "image.png").write_bytes(b"\x89PNG")
    return d


def test_exported_files_are_scanned_by_format_and_no_values_are_kept(tmp_path):
    rep = sc.scan(DET, paths=[str(_exports(tmp_path))])
    by = {Path(s["name"]).name: s for s in rep["sources"]}
    assert set(by) == {"cw.json", "app.log.gz", "chats.jsonl", "crm.csv", "list.json"}      # png skipped
    assert by["cw.json"]["sampled"] == 4 and by["cw.json"]["with_raw_pii"] == 2 and by["cw.json"]["with_tokens"] == 1
    assert by["cw.json"]["entity_types"] == {"PHONE_IN": 1, "AADHAAR": 1}
    assert by["app.log.gz"]["entity_types"] == {"CARD_NUMBER": 1, "UPI_ID": 1}
    assert by["chats.jsonl"]["entity_types"] == {"EMAIL": 1} and by["crm.csv"]["with_raw_pii"] == 1
    assert by["list.json"]["examples"][0]["locator"]["item"] == 1
    assert rep["summary"]["with_raw_pii"] == 5 and _no_values(rep) and _no_values(sc.markdown(rep))


def test_tokens_are_counted_but_never_mistaken_for_raw_data(tmp_path):
    f = tmp_path / "t.log"
    f.write_text("sent <PHONE_IN_a1b2c3d4e5f6> and <AADHAAR_0123456789ab>\n")
    s = sc.scan(DET, paths=[str(f)])["sources"][0]
    assert s["with_tokens"] == 1 and s["with_raw_pii"] == 0


def test_large_files_are_sampled_evenly_up_to_the_limit(tmp_path):
    f = tmp_path / "big.log"
    f.write_text("".join(f"line {i}\n" for i in range(5000)) + f"phone {RAW['phone']}\n")
    s = sc.scan(DET, paths=[str(f)], limit=100)["sources"][0]
    assert s["sampled"] == 100
    with pytest.raises(ValueError):
        sc.scan(DET, paths=[str(f)], limit=0)
    with pytest.raises(ValueError):
        sc.scan(DET, paths=[str(f)], limit=10_001)


# ---- configured stores: read-only ----------------------------------------------------------------------------------
def _digest(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def test_local_stores_are_sampled_without_changing_them(tmp_path):
    import fakeredis
    from sqlalchemy import create_engine, text

    from dpdp_rights.connectors.local import JsonlDatasetConnector, LogFileConnector, RedisCacheConnector, SqlTableConnector

    db = tmp_path / "app.db"
    e = create_engine(f"sqlite:///{db}")
    with e.begin() as c:
        c.execute(text("CREATE TABLE notes (id INTEGER PRIMARY KEY, who TEXT, body TEXT, n INTEGER)"))
        c.execute(text("INSERT INTO notes (who, body, n) VALUES ('a', :b, 1), ('b', 'nothing', 2)"),
                  {"b": f"call {RAW['phone']}"})
    (tmp_path / "eval.jsonl").write_text(json.dumps({"id": 1, "q": f"mail {RAW['email']}"}) + "\n")
    (tmp_path / "app.log").write_text(f"x\npay {RAW['upi']}\n")
    r = fakeredis.FakeRedis()
    r.set("resp:1", f"card {RAW['card']}")
    r.sadd("dpdp:idx:p1", "resp:1")
    before = {p: _digest(p) for p in (db, tmp_path / "eval.jsonl", tmp_path / "app.log")}
    conns = {"notes": SqlTableConnector("notes", url=f"sqlite:///{db}", table="notes"),     # no content column: text cols
             "notes_body": SqlTableConnector("notes_body", url=f"sqlite:///{db}", table="notes", content_column="body"),
             "eval": JsonlDatasetConnector("eval", path=str(tmp_path / "eval.jsonl")),
             "log": LogFileConnector("log", path=str(tmp_path / "app.log")),
             "cache": RedisCacheConnector("cache", client=r)}
    rep = sc.scan(DET, conns)
    by = {s["name"]: s for s in rep["sources"]}
    assert by["notes"]["with_raw_pii"] == 1 and by["notes"]["sampled"] == 2
    assert by["notes_body"]["entity_types"] == {"PHONE_IN": 1}
    assert by["eval"]["entity_types"] == {"EMAIL": 1} and by["log"]["entity_types"] == {"UPI_ID": 1}
    assert by["cache"]["sampled"] == 1 and by["cache"]["entity_types"] == {"CARD_NUMBER": 1}    # index set skipped
    assert {p: _digest(p) for p in before} == before and r.get("resp:1") and _no_values(rep)


def test_aws_stores_are_sampled_read_only(monkeypatch):
    import boto3
    import moto

    from dpdp_rights.connectors.aws import CloudWatchLogsConnector, DynamoDBConnector, S3ObjectsConnector

    monkeypatch.setenv("AWS_DEFAULT_REGION", "ap-south-1")
    with moto.mock_aws():
        s3 = boto3.client("s3", region_name="ap-south-1")
        s3.create_bucket(Bucket="dpdp-scan-test", CreateBucketConfiguration={"LocationConstraint": "ap-south-1"})
        s3.put_object(Bucket="dpdp-scan-test", Key="transcripts/p1/call.txt", Body=f"caller {RAW['phone']}".encode())
        s3.put_object(Bucket="dpdp-scan-test", Key="transcripts/p1/audio.wav", Body=b"RIFF")
        ddb = boto3.resource("dynamodb", region_name="ap-south-1")
        ddb.create_table(TableName="chats", KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
                         AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
                         BillingMode="PAY_PER_REQUEST")
        ddb.Table("chats").put_item(Item={"pk": "p1", "msg": f"aadhaar {RAW['aadhaar']}"})
        logs = boto3.client("logs", region_name="ap-south-1")
        logs.create_log_group(logGroupName="/app")
        logs.create_log_stream(logGroupName="/app", logStreamName="s")
        import time
        logs.put_log_events(logGroupName="/app", logStreamName="s",
                            logEvents=[{"timestamp": int(time.time() * 1000), "message": f"email {RAW['email']}"}])
        conns = {"s3": S3ObjectsConnector("s3", bucket="dpdp-scan-test", prefix_template="transcripts/{principal_id}/", client=s3),
                 "ddb": DynamoDBConnector("ddb", table="chats", partition_key="pk", resource=ddb),
                 "cw": CloudWatchLogsConnector("cw", log_group_names=["/app"], client=logs)}
        rep = sc.scan(DET, conns)
        by = {s["name"]: s for s in rep["sources"]}
        assert by["s3"]["sampled"] == 1 and by["s3"]["entity_types"] == {"PHONE_IN": 1}    # .wav listed, not read
        assert by["ddb"]["entity_types"] == {"AADHAAR": 1} and by["cw"]["entity_types"] == {"EMAIL": 1}
        assert len(s3.list_object_versions(Bucket="dpdp-scan-test").get("Versions", [])) == 2
        assert ddb.Table("chats").scan()["Count"] == 1 and _no_values(rep)


def test_gcp_and_langfuse_stores_are_sampled_through_their_read_apis():
    from dpdp_rights.connectors.gcp import BigQueryConnector, CloudLoggingConnector
    from dpdp_rights.connectors.observability import LangfuseConnector

    class Row(dict):
        def items(self):
            return super().items()

    class BQ:
        def list_rows(self, table, max_results):
            assert table == "p.d.t"
            return [Row(id=1, note=f"pan ABCPE1234F phone {RAW['phone']}")]

        def query(self, *a, **k):
            raise AssertionError("scan must not run queries")

    class Entry:
        log_name, insert_id, payload = "projects/p/logs/app", "i1", {"msg": f"upi {RAW['upi']}"}

    class CL:
        def list_entries(self, filter_, order_by, page_size):
            assert order_by == "timestamp desc"
            return [Entry()]

    calls = []

    def http(method, path, body=None):
        calls.append(method)
        return {"data": [{"id": "t1", "input": {"q": f"email {RAW['email']}"}, "output": "ok"}],
                "meta": {"totalPages": 1}}
    conns = {"bq": BigQueryConnector("bq", table="p.d.t", client=BQ()),
             "cl": CloudLoggingConnector("cl", project="p", client=CL()),
             "lf": LangfuseConnector("lf", public_key="pk", secret_key="sk", http=http)}
    by = {s["name"]: s for s in sc.scan(DET, conns)["sources"]}
    assert by["bq"]["entity_types"] == {"PAN": 1, "PHONE_IN": 1} and by["cl"]["entity_types"] == {"UPI_ID": 1}
    assert by["lf"]["entity_types"] == {"EMAIL": 1} and set(calls) == {"GET"}


def test_stores_that_cannot_be_read_or_fail_are_reported_not_skipped():
    class Blind(Connector):
        type_name = "blind"

    class Broken(Connector):
        type_name = "broken"
        can_sample = True

        def sample(self, limit):
            yield Sample({"id": 1}, "fine")
            raise RuntimeError("access denied")
    rep = sc.scan(DET, {"blind": Blind("blind"), "broken": Broken("broken")})
    by = {s["name"]: s for s in rep["sources"]}
    assert "cannot read content" in by["blind"]["not_sampled"] and "access denied" in by["broken"]["error"]
    assert rep["summary"]["not_sampled"] == ["blind"] and rep["summary"]["errors"] == ["broken"]
    assert "not sampled" in sc.markdown(rep) and "error" in sc.markdown(rep)


# ---- draft inventory -----------------------------------------------------------------------------------------------
def test_draft_inventory_loads_into_the_coverage_report(tmp_path):
    from dpdp_rights.connectors.local import LogFileConnector
    from dpdp_rights.core.config import FrameworkConfig
    from dpdp_rights.delivery.inventory import Inventory, coverage_report

    (tmp_path / "app.log").write_text(f"phone {RAW['phone']}\n")
    rep = sc.scan(DET, {"app_log": LogFileConnector("app_log", path=str(tmp_path / "app.log"))},
                  paths=[str(_exports(tmp_path))])
    inv = Inventory.model_validate(sc.draft_inventory(rep, "Acme Insurance"))
    log = next(s for s in inv.systems if s.name == "app_log")
    assert log.category == "logs" and log.connector == "app_log" and "PHONE_IN" in log.data_elements
    assert log.description.startswith("DRAFT") and log.purposes == [] and log.tested_on is None
    cfg = FrameworkConfig.model_validate({"connectors": [{"name": "app_log", "type": "log_file",
                                                          "options": {"path": str(tmp_path / "app.log")}}]})
    cov = coverage_report(inv, cfg)
    assert cov["summary"]["systems"] == len(inv.systems)


# ---- CLI ------------------------------------------------------------------------------------------------------------
def test_cli_scans_files_without_a_config_and_never_the_demo_default(tmp_path, capsys, monkeypatch):
    from dpdp_rights.cli import main

    monkeypatch.chdir(Path(__file__).parents[1])          # where config/dpdp.local.yaml exists
    d = _exports(tmp_path)
    main(["scan", "--path", str(d), "--format", "json", "--inventory-out", str(tmp_path / "draft.yaml")])
    rep = json.loads(capsys.readouterr().out)
    assert all(s["kind"] == "file" for s in rep["sources"]) and (tmp_path / "draft.yaml").exists()
    assert (tmp_path / "draft.yaml").read_text().startswith("# DRAFT")
    with pytest.raises(SystemExit, match="not overwriting"):
        main(["scan", "--path", str(d), "--inventory-out", str(tmp_path / "draft.yaml")])
    with pytest.raises(SystemExit, match="nothing to scan"):
        main(["scan"])
    with pytest.raises(SystemExit, match="llm"):
        main(["scan", "--path", str(d), "--detectors", "regex,llm"])


def test_report_states_scope_and_limits_up_front(tmp_path):
    from dpdp_rights.connectors.base import Connector

    class Blind(Connector):
        type_name = "blind"
    rep = sc.scan(DET, {"blind": Blind("blind")}, paths=[str(_exports(tmp_path))], limit=50)
    scope = rep["scope"]
    assert scope["complete_inventory"] is False and scope["sources_not_sampled"] == ["blind"]
    assert scope["items_sampled"] == sum(s["sampled"] for s in rep["sources"]) and scope["limit_per_source"] == 50
    md = sc.markdown(rep)
    assert md.index("Scope and limits") < md.index("| Source |")          # before the results
    assert "not a complete inventory" in md and "Not sampled (cannot read content): blind" in md


def test_a_clean_sample_never_marks_a_system_out_of_scope(tmp_path):
    from dpdp_rights.connectors.local import LogFileConnector
    from dpdp_rights.delivery.inventory import Inventory

    (tmp_path / "quiet.log").write_text("ok\nok\n")
    rep = sc.scan(DET, {"quiet": LogFileConnector("quiet", path=str(tmp_path / "quiet.log"))})
    entry = Inventory.model_validate(sc.draft_inventory(rep)).systems[0]
    assert entry.holds_personal_data is True and "does not show" in entry.notes
    assert "NOT a complete inventory" in sc.DRAFT_HEADER
