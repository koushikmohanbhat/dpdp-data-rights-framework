"""The example plug-in: discovered through entry points, used from config, and conformant."""
import csv
import json

from dpdp_example_plugin.csv_connector import FIELDS, CsvRecordsConnector

from dpdp_rights import DataRightsFramework, plugins
from dpdp_rights.core.config import FrameworkConfig
from dpdp_rights.testing.conformance import ConnectorConformance, ConnectorHarness


class CsvHarness(ConnectorHarness):
    def __init__(self, tmp_path):
        self.path = tmp_path / "records.csv"

    def connector(self):
        return CsvRecordsConnector("sut", str(self.path))

    def write(self, record_id, content, principal_id):
        new = not self.path.exists()
        with self.path.open("a", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=FIELDS)
            if new:
                w.writeheader()
            w.writerow({"id": record_id, "principal_id": principal_id, "text": content})
        return {"id": record_id}

    def read(self, locator):
        if not self.path.exists():
            return None
        with self.path.open(newline="", encoding="utf-8") as f:
            return next((r["text"] for r in csv.DictReader(f) if r["id"] == locator["id"]), None)


class TestCsvRecordsConformance(ConnectorConformance):
    def make_harness(self, tmp_path):
        return CsvHarness(tmp_path)


def test_entry_points_are_discovered():
    plugins.reset()
    names = {(p.group, p.name): p for p in plugins.listing()}
    for key in [("connectors", "csv_records"), ("detectors", "employee_id"), ("notifiers", "jsonl_outbox")]:
        assert key in names and names[key].source.startswith("dpdp-rights-example-plugin"), key


def test_used_from_config(tmp_path):
    cfg = FrameworkConfig.model_validate({
        "vault": {"key_wrapper": "local", "local_master_key_path": str(tmp_path / "k")},
        "lineage": {"url": f"sqlite:///{tmp_path}/l.db"},
        "purposes": [{"id": "hr", "description": "HR"}],
        "pii": {"detectors": ["regex", "employee_id"]},
        "connectors": [{"name": "hr_export", "type": "csv_records", "options": {"path": str(tmp_path / "hr.csv")}}],
        "notifications": [{"type": "jsonl_outbox", "options": {"path": str(tmp_path / "outbox.jsonl")}}],
    })
    dpdp = DataRightsFramework(cfg)
    pid = dpdp.principal("emp-42")
    dpdp.grant_consent(pid, "hr")
    with dpdp.context(pid, purpose="hr"):
        safe = dpdp.protect("Leave request from EMP-004211")
    assert "EMP-004211" not in safe.text
    h = CsvHarness(tmp_path)
    h.path = tmp_path / "hr.csv"
    h.write("r1", safe.text, pid)
    out = dpdp.erase(pid)
    assert out["status"] == "completed" and h.read({"id": "r1"}) is None
    event = json.loads((tmp_path / "outbox.jsonl").read_text().splitlines()[0])
    assert event["event"] == "request_completed"
