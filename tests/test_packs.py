"""Domain packs: scenarios pass, init produces a working engagement folder, client configs can be tested,
and the detection additions the packs rely on."""
import pytest
import yaml

from dpdp_rights import FrameworkConfig, packs
from dpdp_rights.core.config import PIIConfig
from dpdp_rights.delivery.inventory import Inventory, coverage_report
from dpdp_rights.pii.detectors import build_detector
from dpdp_rights.rights.rules import resolve


@pytest.mark.parametrize("pack_id", packs.available())
def test_pack_scenarios_pass(pack_id):
    res = packs.test(pack_id)
    assert res and all(r.ok for r in res), [(r.scenario, r.step, r.failures) for r in res if not r.ok]


@pytest.mark.parametrize("pack_id", packs.available())
def test_pack_is_complete_and_valid(pack_id, tmp_path):
    p = packs.load(pack_id)
    assert {"id", "title", "version", "sources", "config", "reviewed"} <= set(p)
    holds = [x for x in p["config"]["purposes"] if x.get("legal_hold_basis")]
    assert holds and all("counsel" in x["legal_hold_basis"].lower() or "validate" in x["legal_hold_basis"].lower()
                         for x in holds)
    cfg = FrameworkConfig.from_dict({"purposes": p["config"]["purposes"], "policy": p["config"]["policy"],
                                     "pii": p["config"]["pii"], "rights": p["config"]["rights"]})
    resolve(cfg.rights.rule_set, None, cfg.rights.overrides)       # overrides stay within prescribed limits
    build_detector(cfg.pii)                                         # patterns compile
    written = packs.init(pack_id, str(tmp_path / "eng"))
    assert {"dpdp.yaml", "inventory.yaml", "scenarios.yaml", "questions.md", "PACK-README.md"} == \
        {w.rsplit("/", 1)[1] for w in written}
    merged = FrameworkConfig.load(str(tmp_path / "eng" / "dpdp.yaml"))
    rep = coverage_report(Inventory.load(str(tmp_path / "eng" / "inventory.yaml")), merged)
    assert rep["summary"]["in_scope"] >= 10
    purposes = {x.id for x in merged.purposes}
    assert all(set(s.purposes) <= purposes for s in Inventory.load(str(tmp_path / "eng" / "inventory.yaml")).systems)
    with pytest.raises(FileExistsError):
        packs.init(pack_id, str(tmp_path / "eng"))


def test_init_merges_into_a_base_config(tmp_path):
    packs.init("lending", str(tmp_path / "e"), base="config/dpdp.local.yaml")
    raw = yaml.safe_load((tmp_path / "e" / "dpdp.yaml").read_text())
    assert raw["provider"]["type"].startswith("${DPDP_PROVIDER")             # kept from the base
    assert {p["id"] for p in raw["purposes"]} >= {"loan_account", "kyc_aml"}  # replaced by the pack
    assert raw["rights"]["channels"] and any(r["store"] == "collections_agency" for r in raw["rights"]["recipients"])
    assert raw["policy"]["rules"][0]["kind"] == "eval_row"


def test_client_config_is_tested_and_a_missing_hold_is_caught(tmp_path):
    packs.init("insurance", str(tmp_path / "c"))
    path = tmp_path / "c" / "dpdp.yaml"
    raw = yaml.safe_load(path.read_text())
    for p in raw["purposes"]:
        if p["id"] == "kyc_aml":
            p.pop("legal_hold_basis")                    # a client config that forgot the PMLA hold
    path.write_text(yaml.safe_dump(raw))
    res = packs.test("insurance", config=str(path))
    bad = [r for r in res if not r.ok]
    assert len(bad) == 1 and "kyc-2: action delete != retain_legal_hold" in bad[0].failures


def test_cli_packs(tmp_path, capsys):
    from dpdp_rights.cli import main
    main(["packs", "list"])
    assert "insurance" in capsys.readouterr().out
    with pytest.raises(SystemExit) as e:
        main(["packs", "test", "all"])
    assert e.value.code == 0
    bad = tmp_path / "s.yaml"
    bad.write_text(yaml.safe_dump({"detection": [{"text": "nothing here", "types": ["PAN"]}]}))
    with pytest.raises(SystemExit) as e:
        main(["packs", "test", "insurance", "--scenarios", str(bad)])
    assert e.value.code == 1 and "missed PAN" in capsys.readouterr().out
    with pytest.raises(KeyError):
        packs.load("aviation")


# ---- detection additions ---------------------------------------------------------------------------
def test_patterns_need_their_context_and_valid_types():
    d = build_detector(PIIConfig(patterns=[{"type": "UHID", "regex": r"\b\d{8}\b", "context": ["uhid", "mrn"]}]))
    found = [(e.type, e.text) for e in d.detect("UHID 44556677; ref 11223344; MRN: 55667788")]
    assert ("UHID", "44556677") in found and ("UHID", "55667788") in found and ("UHID", "11223344") not in found
    with pytest.raises(ValueError, match="UPPER_SNAKE_CASE"):
        build_detector(PIIConfig(patterns=[{"type": "uhid", "regex": "x"}]))
    with pytest.raises(ValueError, match="invalid regex"):
        build_detector(PIIConfig(patterns=[{"type": "UHID", "regex": "("}]))


def test_abha_address_ckyc_and_account_precedence():
    d = build_detector(PIIConfig())
    types = lambda t: {e.type for e in d.detect(t)}   # noqa: E731
    assert types("ABHA address priya.sharma@abdm") == {"ABHA_ADDRESS"}
    assert types("pay rahulv@okhdfc") == {"UPI_ID"}
    assert types("CKYC number 12345678901234") == {"CKYC_NUMBER"}
    assert types("a/c 50100123456789") == {"BANK_ACCOUNT"}
    assert types("write to a@abdm.gov.in") == {"EMAIL"}


def test_summary_of_one_person_is_deleted_not_regenerated():
    from dpdp_rights.core.config import PolicyConfig
    from dpdp_rights.core.models import Action, Artifact
    from dpdp_rights.erasure.policy import PolicyEngine, PolicyInput
    eng = PolicyEngine(PolicyConfig(aggregate_k_threshold=5))
    one = PolicyInput(Artifact("a", "summary", "s", {}), "transform", 1, 1, None, False)
    many = PolicyInput(Artifact("b", "summary", "s", {}), "transform", 1, 3, None, False)
    assert eng.decide(one)[0] == Action.DELETE and eng.decide(many)[0] == Action.REGENERATE
