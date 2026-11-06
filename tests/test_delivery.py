"""Capability matrix and deployment coverage report."""
from datetime import date
from pathlib import Path

import pytest

from dpdp_rights.cli import main
from dpdp_rights.core.config import FrameworkConfig
from dpdp_rights.delivery.capabilities import capabilities_doc, load_matrix
from dpdp_rights.delivery.inventory import Inventory, coverage_report, to_html, to_markdown

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples/insurance_onboarding/inventory.yaml"
CONFIG = ROOT / "config/dpdp.local.yaml"


def test_every_connector_declares_capabilities():
    m = load_matrix()
    assert len(m) >= 20
    for name, c in m.items():
        assert c["discover"] in ("native", "lineage"), name
        assert c["verify"] in ("rescan", "rediscover", "api_confirmation", "action_status", "none"), name
        assert c["deletion"] in ("item", "container", "revoke", "none"), name
    assert m["aws_agentcore_identity"]["deletion"] == "revoke"
    assert m["aws_cloudwatch_logs"]["individual_deletion"] is False
    assert m["sql_table"]["redact_in_place"] is True


def test_capability_doc_is_current():
    assert (ROOT / "docs/capabilities.md").read_text() == capabilities_doc(), \
        "regenerate: dpdp-rights capabilities --format doc > docs/capabilities.md"


def _report(inv=None, today=date(2026, 11, 6)):
    return coverage_report(inv or Inventory.load(str(EXAMPLE)), FrameworkConfig.load(str(CONFIG)), today=today)


def test_example_inventory_coverage():
    rep = _report()
    s = rep["summary"]
    assert (s["in_scope"], s["automated"], s["manual"], s["gaps"]) == (10, 8, 1, 1)
    status = {r["system"]: r["status"] for r in rep["systems"]}
    assert status["Email campaign platform"] == "gap"
    assert status["Application log"] == "automated_with_limits"
    assert status["Product catalogue"] == "out_of_scope"
    msgs = " ".join(f["message"] for f in rep["findings"])
    assert "under one year" in msgs and "outside India" in msgs and "no contract reference" in msgs
    assert "Coverage report" in to_markdown(rep) and "<table>" in to_html(rep)


def test_coverage_catches_config_mismatches():
    inv = Inventory.model_validate({
        "engagement": {"client": "T"},
        "systems": [{"name": "CRM", "connector": "crm", "purposes": ["sales"]},
                    {"name": "Old app DB", "connector": "applications", "tested_on": "2025-01-01"}]})
    rep = _report(inv)
    msgs = [f["message"] for f in rep["findings"]]
    assert any("'crm' is not in the framework config" in m for m in msgs)
    assert any("purpose 'sales' is not defined" in m for m in msgs)
    assert any("retest" in m for m in msgs)
    assert any("'kyc_records' (sql_table) is configured but no system" in m for m in msgs)


def test_cli_coverage_fail_on_gaps(tmp_path, capsys):
    out = tmp_path / "c.json"
    with pytest.raises(SystemExit) as e:
        main(["-c", str(CONFIG), "coverage", "--inventory", str(EXAMPLE), "--format", "json",
              "--output", str(out), "--fail-on-gaps"])
    assert e.value.code == 1 and out.exists()


def test_inventory_template_is_valid():
    inv = Inventory.load(str(ROOT / "partner-pack/inventory.template.yaml"))
    assert inv.systems and inv.systems[0].category == "database"
