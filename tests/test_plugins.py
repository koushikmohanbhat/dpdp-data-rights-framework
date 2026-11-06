"""Plug-in registry (entry points), plug-in guardrails, and notifications."""
import hashlib
import hmac
import json
import sys
import types
from importlib import metadata

import pytest
from _db import lineage_url

from dpdp_rights import DataRightsFramework, plugins
from dpdp_rights.connectors.base import Capabilities, Connector
from dpdp_rights.core.config import FrameworkConfig
from dpdp_rights.core.models import Action
from dpdp_rights.notify import WebhookNotifier
from dpdp_rights.pii.detectors import Entity
from dpdp_rights.security.guardrails import production_issues


class NoteConnector(Connector):
    supports = {Action.DELETE}
    capabilities = Capabilities(store="Test notes", discover="lineage", discover_how="registered items",
                                verify="none", verify_how="-")
    deleted: list = []

    def _delete(self, artifact, ctx, fallback_from=None):
        NoteConnector.deleted.append(artifact.locator["id"])
        return self._ok(artifact, Action.DELETE)


class BareConnector(Connector):          # no capabilities declared
    def _delete(self, artifact, ctx, fallback_from=None):
        return self._ok(artifact, Action.DELETE)


class EmployeeIdDetector:
    ner = False

    def __init__(self, prefix="EMP"):
        self.prefix = prefix

    def detect(self, text):
        i = text.find(self.prefix + "-")
        return [Entity("EMPLOYEE_ID", i, i + len(self.prefix) + 7, text[i:i + len(self.prefix) + 7])] if i >= 0 else []


class Recorder:
    events: list = []

    def __init__(self, **opts):
        self.opts = opts

    def notify(self, event, payload):
        Recorder.events.append((event, payload))


@pytest.fixture
def fake_plugins(monkeypatch):
    mod = types.ModuleType("acme_dpdp")
    mod.NoteConnector, mod.BareConnector = NoteConnector, BareConnector
    mod.EmployeeIdDetector, mod.Recorder = EmployeeIdDetector, Recorder
    mod.broken = None
    sys.modules["acme_dpdp"] = mod
    eps = {
        "dpdp_rights.connectors": [("notes", "acme_dpdp:NoteConnector"), ("bare", "acme_dpdp:BareConnector"),
                                   ("sql_table", "acme_dpdp:NoteConnector")],     # clash: ignored
        "dpdp_rights.detectors": [("employee_id", "acme_dpdp:EmployeeIdDetector")],
        "dpdp_rights.notifiers": [("recorder", "acme_dpdp:Recorder")],
        "dpdp_rights.providers": [("broken", "acme_dpdp:does_not_exist")],
    }

    def entry_points(group=None, **kw):
        return metadata.EntryPoints(metadata.EntryPoint(n, v, group) for n, v in eps.get(group, []))

    monkeypatch.setattr(metadata, "entry_points", entry_points)
    plugins.reset()
    Recorder.events.clear()
    NoteConnector.deleted.clear()
    yield
    plugins.reset()
    sys.modules.pop("acme_dpdp", None)


def _cfg(tmp_path, **extra):
    base = {"vault": {"key_wrapper": "local", "local_master_key_path": str(tmp_path / "k")},
            "lineage": {"url": lineage_url(tmp_path)},
            "purposes": [{"id": "hr", "description": "HR"}]}
    base.update(extra)
    return FrameworkConfig.model_validate(base)


def test_plugins_are_discovered_and_used(fake_plugins, tmp_path):
    cfg = _cfg(tmp_path, connectors=[{"name": "notes", "type": "notes"}],
               pii={"detectors": ["regex", "employee_id"], "detector_options": {"employee_id": {"prefix": "EMP"}}},
               notifications=[{"type": "recorder", "options": {"channel": "dpo"}}])
    dpdp = DataRightsFramework(cfg)
    pid = dpdp.principal("e-1")
    dpdp.grant_consent(pid, "hr")
    with dpdp.context(pid, purpose="hr"):
        safe = dpdp.protect("Employee EMP-123456 asked about leave")
        dpdp.track_artifact("record", "notes", {"id": "n1"}, content=safe.text, element_ids=safe.element_ids)
    assert "EMP-123456" not in safe.text and "<EMPLOYEE_ID_" in safe.text
    out = dpdp.erase(pid)
    assert NoteConnector.deleted == ["n1"] and out["status"] == "completed"
    (event, payload), = Recorder.events
    assert event == "request_completed" and payload["request_id"] == out["request_id"]
    assert "EMP-123456" not in json.dumps(payload)                          # no personal data in notifications


def test_listing_reports_sources_and_errors(fake_plugins):
    rows = [r for r in plugins.listing() if r.group == "connectors" and r.name == "sql_table"]
    assert [r.source for r in rows][0] == "builtin" and "clashes" in rows[1].error   # the built-in wins
    assert plugins.get("connectors", "sql_table").__name__ == "SqlTableConnector"
    with pytest.raises(ValueError, match="failed to load"):
        plugins.get("providers", "broken")
    with pytest.raises(ValueError, match="Unknown connector 'nope'.*entry point"):
        plugins.get("connectors", "nope")


def test_guardrails_require_capabilities_and_known_plugins(fake_plugins, tmp_path):
    cfg = _cfg(tmp_path, environment="production",
               connectors=[{"name": "b", "type": "bare"}, {"name": "x", "type": "missing_type"}],
               notifications=[{"type": "webhook", "options": {"url": "https://hooks.example.in/dpdp"}}],
               pii={"detectors": ["regex", "employee_id"]})
    msgs = [m for _, m in production_issues(cfg)]
    assert any("'b' (bare) declares no capabilities" in m for m in msgs)
    assert any("missing_type" in m for m in msgs)
    assert any("webhook notifier has no secret" in m for m in msgs)
    assert any("no NER detector" in m for m in msgs)                         # employee_id is not NER


def test_webhook_is_signed_and_failures_do_not_block(tmp_path, caplog):
    sent = {}

    class Resp:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def opener(req, timeout):
        sent["body"], sent["sig"] = req.data, req.get_header("X-dpdp-signature")
        return Resp()

    WebhookNotifier("https://hooks.example.in/x", secret="s3cret", opener=opener).notify("request_completed", {"a": 1})
    assert sent["sig"] == "sha256=" + hmac.new(b"s3cret", sent["body"], hashlib.sha256).hexdigest()
    with pytest.raises(ValueError, match="https"):
        WebhookNotifier("http://example.in/x")

    def boom(req, timeout):
        raise OSError("connection refused")

    dpdp = DataRightsFramework(_cfg(tmp_path, notifications=[{"type": "webhook", "options": {
        "url": "https://hooks.example.in/x"}}]))
    dpdp.notifications._targets[0][1]._open = boom
    pid = dpdp.principal("w-1")
    assert dpdp.erase(pid)["status"] == "completed"                          # the failed webhook is only logged
    assert "notifier webhook failed" in caplog.text
