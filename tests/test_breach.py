"""Personal data breach impact assessment (Act s.8(6), Rules r.7): docs/breach.md."""
import json
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from test_rights import _cfg, _inventory, _person

from dpdp_rights import DataRightsFramework
from dpdp_rights.api.app import create_app
from dpdp_rights.breach import BreachError
from dpdp_rights.core.models import utcnow
from dpdp_rights.evidence.bundle import verify_bundle
from dpdp_rights.rights import RuleError, resolve
from dpdp_rights.security.auth import hash_api_key

IST = timezone(timedelta(hours=5, minutes=30))


def _iso(dt):
    return dt.isoformat()


@pytest.fixture
def two(workdir):
    tmp, db = workdir
    f = DataRightsFramework(_cfg(tmp))
    p1, _ = _person(f, db, "p1", "mail p1@example.in phone 9876543210")
    p2, _ = _person(f, db, "p2", "mail p2@example.in")
    return f, db, p1, p2


def _assess(f, **kw):
    kw.setdefault("stores", ["records"])
    kw.setdefault("assessed_by", "dpo:asha")
    return f.breach.assess(**kw)


def _by_pid(rep):
    return {p["principal_id"]: p for p in rep["affected"]}


# ---- who is affected, and how ------------------------------------------------------------------------------
def test_people_in_a_breached_store_are_listed_with_categories_exposure_and_deadlines(two):
    f, _, p1, p2 = two
    aware = datetime(2026, 11, 18, 9, 0, tzinfo=IST)
    r = _assess(f, aware_at=_iso(aware), start=_iso(aware - timedelta(hours=10)), nature="Bucket exposed")
    people = _by_pid(r)
    assert set(people) == {p1, p2} and r["totals"]["affected"] == 2
    assert {"EMAIL", "PHONE_IN"} <= set(people[p1]["element_types"]) and "PHONE_IN" not in people[p2]["element_types"]
    assert all(p["exposure"] == "tokens" and p["contact_on_record"] and not p["mentioned_only"]
               for p in people.values())
    assert r["totals"]["by_exposure"] == {"raw": 0, "tokens_readable": 0, "tokens": 2, "key_destroyed": 0}
    assert r["deadlines"]["board_detailed"]["due_by"] == _iso(aware + timedelta(hours=72))
    assert r["deadlines"]["board_detailed"]["extendable"] and r["deadlines"]["principals"]["when"] == "without delay"
    assert r["rule_set"]["version"] == "2025.11-3" and r["threshold"] == "none"
    assert r["stores"][0] == r["stores"][0] | {"store": "records", "artifacts": 2, "people": 2, "tracked": True}
    assert r["signed"] and f.breach.verify(r["breach_id"])["ok"]


def test_raw_values_are_reported_as_raw(two):
    f, _, p1, _ = two
    with f.context(p1, purpose="service"):
        s = f.protect("legacy note for p1@example.in")
        f.track_artifact("record", "records", {"id": "legacy"}, element_ids=s.element_ids, contains_raw_pii=True)
    r = _assess(f)
    assert _by_pid(r)[p1]["exposure"] == "raw" and r["totals"]["by_exposure"]["raw"] == 1
    assert r["stores"][0]["raw_artifacts"] == 1
    assert "may be readable" in f.breach.drafts(r["breach_id"])["board_initial"]


def test_a_compromised_vault_makes_tokens_readable(two):
    f, *_ = two
    r = _assess(f, vault_compromised=True)
    assert r["totals"]["by_exposure"]["tokens_readable"] == 2 and r["vault_compromised"]
    assert any("vault was compromised" in n for n in r["notes"])
    assert "rotate the key-encryption key" in f.breach.drafts(r["breach_id"])["board_detailed"]
    assert _assess(f, stores=[], vault_compromised=True)["totals"]["affected"] == 0   # vault alone is valid input


def test_people_already_erased_are_counted_but_get_no_notice(two):
    f, _, p1, p2 = two
    f.erase(p1)
    r = _assess(f)
    assert p1 not in _by_pid(r)                                       # their record was deleted by the erasure
    maybe = {p["principal_id"]: p for p in r["possibly_affected"]}
    assert maybe[p1]["exposure"] == "key_destroyed" and maybe[p1]["status"] == "erased"
    assert "since erased" in maybe[p1]["reasons"][0]
    notices = f.breach.drafts(r["breach_id"])["notices"]
    assert [n["principal_id"] for n in notices] == [p2]


def test_someone_only_mentioned_in_another_persons_record_is_affected_and_marked(workdir):
    tmp, db = workdir
    f = DataRightsFramework(_cfg(tmp))
    rahul, _ = _person(f, db, "rahul", "mail rahul@example.in")
    priya = f.principal("priya")
    f.register_identifier(priya, "EMAIL", "priya@example.in")
    with f.context(rahul, purpose="service"):
        s = f.protect("nominee priya@example.in")
        f.track_artifact("record", "records", {"id": "rahul-nominee"}, content=s.text, element_ids=s.element_ids)
    people = _by_pid(_assess(f))
    assert people[rahul]["mentioned_only"] is False
    assert priya in people and people[priya]["mentioned_only"] is True


def test_people_behind_a_derived_summary_are_possibly_affected(two):
    f, _, p1, p2 = two
    parents = [a.artifact_id for a in f.store.artifacts_in_stores(["records"])]
    with f.context(p1, purpose="service"):
        f.track_artifact("summary", "summaries", {"id": "weekly"}, parents=parents, edge_type="aggregate")
    r = _assess(f, stores=["summaries"])
    assert r["totals"]["affected"] == 0
    maybe = {p["principal_id"]: p for p in r["possibly_affected"]}
    assert set(maybe) == {p1, p2} and "derived summary" in maybe[p1]["reasons"][0]
    assert any("not a configured connector" in n for n in r["notes"])


# ---- the window and time zones ------------------------------------------------------------------------------
def test_artifacts_created_after_the_breach_ended_are_excluded_across_time_zones(two):
    f, db, p1, p2 = two
    cut = utcnow()
    p3, _ = _person(f, db, "p3", "mail p3@example.in")
    r = _assess(f, end=_iso(cut.astimezone(IST)))                    # same instant, written in IST
    assert set(_by_pid(r)) == {p1, p2}
    later = _assess(f, end=_iso((cut + timedelta(minutes=1)).astimezone(IST)))
    assert p3 in _by_pid(later)


def test_times_read_back_with_their_offset(two):
    f, *_ = two
    r = _assess(f, aware_at="2026-11-18T09:00:00+05:30", start="2026-11-17T22:00:00+05:30")
    row = next(x for x in f.breach.list() if x["breach_id"] == r["breach_id"])
    assert row["aware_at"] == "2026-11-18T09:00:00+05:30"
    assert row["board_detailed_due_by"] == "2026-11-21T09:00:00+05:30"
    stored = f.store.breach_assessments(r["breach_id"])[0]
    aware = stored["aware_at"] if stored["aware_at"].tzinfo else stored["aware_at"].replace(tzinfo=timezone.utc)
    assert aware == datetime(2026, 11, 18, 3, 30, tzinfo=timezone.utc)   # stored as UTC, never 09:00 UTC


@pytest.mark.parametrize("kw,msg", [
    ({"stores": [], "systems": []}, "name at least one"),
    ({"start": "2026-11-18T10:00:00+05:30", "end": "2026-11-18T09:00:00+05:30"}, "start is after end"),
    ({"end": _iso(utcnow() + timedelta(days=1))}, "in the future"),
    ({"aware_at": "yesterday"}, "not an ISO 8601 time"),
    ({"assessed_by": ""}, "assessed_by is required"),
    ({"breach_id": "brc_nope"}, "unknown breach"),
    ({"systems": ["Call recordings"]}, "inventory_path is not set"),
])
def test_invalid_assessments_are_refused(two, kw, msg):
    f, *_ = two
    with pytest.raises(BreachError, match=msg):
        _assess(f, **kw)


# ---- systems the framework cannot see ----------------------------------------------------------------------
def test_untracked_stores_and_systems_are_reported_not_counted_as_zero(workdir):
    tmp, db = workdir
    systems = [{"name": "Records", "category": "database", "data_elements": ["EMAIL"], "purposes": ["service"],
                "connector": "records", "platform": "Aurora", "region": "ap-south-1", "processor": "Acme Hosting",
                "processor_contract": "MSA-7"},
               {"name": "Call recordings", "category": "saas", "data_elements": ["PHONE_IN"], "purposes": ["service"],
                "manual_procedure": "CC-07", "platform": "Cloud contact centre", "processor": "VoiceCo"}]
    f = DataRightsFramework(_cfg(tmp, rights=_cfg(tmp).rights.model_dump() | {"inventory_path": _inventory(tmp, systems)}))
    _person(f, db, "p1")
    r = f.breach.assess(systems=["Records", "Call recordings"], stores=["empty_store"], assessed_by="dpo")
    rec = next(s for s in r["stores"] if s["store"] == "records")
    assert rec | {"system": "Records", "region": "ap-south-1", "processor": "Acme Hosting",
                  "processor_contract": "MSA-7"} == rec
    assert r["untracked_systems"][0]["system"] == "Call recordings"
    assert r["untracked_systems"][0]["processor"] == "VoiceCo"
    assert any("'empty_store' has no lineage records" in n for n in r["notes"])
    assert any("'Call recordings' has no connector" in n for n in r["notes"])
    d = f.breach.drafts(r["breach_id"])
    assert "**Incomplete:**" in d["board_initial"] and "affected people not known" in d["board_initial"]
    with pytest.raises(BreachError, match="not in the inventory"):
        f.breach.assess(systems=["Nope"], assessed_by="dpo")


# ---- drafts, re-assessment, evidence -----------------------------------------------------------------------
def test_drafts_follow_rule_7_and_never_contain_personal_values(two):
    f, *_ = two
    r = _assess(f, nature="Log bucket exposed", start="2026-11-17T22:00:00+05:30",
                aware_at="2026-11-18T09:00:00+05:30")
    d = f.breach.drafts(r["breach_id"])
    everything = d["board_initial"] + d["board_detailed"] + json.dumps(d["notices"])
    for value in ("p1@example.in", "p2@example.in", "9876543210"):
        assert value not in everything
    for heading in ("Likely impact", "Facts: events, circumstances and reasons",
                    "Findings regarding the person who caused the breach", "Remedial measures to prevent recurrence",
                    "Intimations given to affected Data Principals"):
        assert heading in d["board_initial"] + d["board_detailed"], heading
    assert "21 Nov 2026, 09:00 (UTC+05:30)" in d["board_detailed"] and "[DPO:" in d["board_detailed"]
    assert "until at least" in d["board_initial"]                       # end not given: not presented as known
    n = d["notices"][0]
    assert n["basis"] == "Rules r.7(1)(a)" and "dpo@insurer.example" in n["text"]
    for part in ("What happened", "What it involved", "What this may mean for you", "What we have done",
                 "What you can do", "Questions"):
        assert part in n["text"]


def test_a_breach_can_be_reassessed_and_keeps_its_history(two):
    f, db, *_ = two
    first = _assess(f)
    _person(f, db, "p9", "mail p9@example.in")
    again = _assess(f, breach_id=first["breach_id"])
    got = f.breach.get(first["breach_id"])
    assert again["breach_id"] == first["breach_id"] and got["assessment_id"] == again["assessment_id"]
    assert [h["affected"] for h in got["history"]] == [2, 3]
    assert len([b for b in f.breach.list() if b["breach_id"] == first["breach_id"]]) == 1


def test_stored_assessments_are_signed_and_tampering_is_detected(two):
    f, *_ = two
    r = _assess(f)
    from sqlalchemy import update

    from dpdp_rights.lineage.store import breach_assessment
    rep = dict(f.store.breach_assessments(r["breach_id"])[0]["report"])
    rep["totals"] = rep["totals"] | {"affected": 0}
    with f.store.engine.begin() as c:
        c.execute(update(breach_assessment).where(breach_assessment.c.breach_id == r["breach_id"]).values(report=rep))
    v = f.breach.verify(r["breach_id"])
    assert not v["ok"] and v["assessments"][0]["hash_ok"] is False


def test_exported_bundle_verifies_offline_and_detects_changes(two, tmp_path):
    import zipfile
    f, *_ = two
    r = _assess(f)
    out = f.breach.export(r["breach_id"], str(tmp_path / "b.zip"))
    assert out["files"] == ["board-detailed.md", "board-initial.md", "notices.jsonl", "report.json", "summary.md"]
    assert verify_bundle(str(tmp_path / "b.zip"))["ok"]
    bad = tmp_path / "bad.zip"
    with zipfile.ZipFile(tmp_path / "b.zip") as zin, zipfile.ZipFile(bad, "w") as zout:
        for item in zin.infolist():
            data = zin.read(item.filename)
            zout.writestr(item, data.replace(b'"affected": 2', b'"affected": 0') if item.filename == "report.json"
                          else data)
    assert not verify_bundle(str(bad))["ok"]


# ---- rule set ----------------------------------------------------------------------------------------------
def test_rule_set_carries_the_breach_timings(tmp_path):
    rs, _ = resolve()
    b = rs.breach()
    assert rs.version == "2025.11-3" and b["board_detailed"]["within_hours"] == 72
    assert b["principals"]["basis"] == "Rules r.7(1)(a)" and len(b["principals"]["contents"]) == 5
    assert len(b["board_detailed"]["contents"]) == 6
    import yaml

    from dpdp_rights.rights import rules as rulesmod
    data = yaml.safe_load(next(p for p in rulesmod.Path(rulesmod.__file__).parent.joinpath("rulesets").glob("*.yaml"))
                          .read_text())
    data["breach"]["board_detailed"]["within_hours"] = 0
    with pytest.raises(RuleError, match="within_hours must be a positive integer"):
        rulesmod._validate(data, "test")


# ---- API and CLI -------------------------------------------------------------------------------------------
def test_api_roles_and_the_assessor_is_the_caller(workdir):
    tmp, db = workdir
    f = DataRightsFramework(_cfg(tmp, api={"auth": {"mode": "api_key", "api_keys": [
        {"name": "app", "sha256": hash_api_key("svc"), "roles": ["service"]},
        {"name": "asha", "sha256": hash_api_key("dpo"), "roles": ["dpo"]},
        {"name": "ravi", "sha256": hash_api_key("rev"), "roles": ["reviewer"]}]}}))
    _person(f, db, "p1")
    c = TestClient(create_app(f))
    dpo, rev, svc = ({"X-API-Key": k} for k in ("dpo", "rev", "svc"))
    body = {"stores": ["records"], "aware_at": "2026-11-18T09:00:00+05:30", "nature": "test"}
    assert c.post("/v1/breaches", headers=svc, json=body).status_code == 403
    assert c.post("/v1/breaches", headers=rev, json=body).status_code == 403
    r = c.post("/v1/breaches", headers=dpo, json=body | {"assessed_by": "someone-else"})
    assert r.status_code == 201 and r.json()["assessed_by"] == "api_key:asha"     # body cannot set the assessor
    bid = r.json()["breach_id"]
    assert c.get("/v1/breaches", headers=rev).json()[0]["breach_id"] == bid
    assert c.get(f"/v1/breaches/{bid}", headers=rev).json()["totals"]["affected"] == 1
    assert c.get(f"/v1/breaches/{bid}/drafts", headers=rev).status_code == 403
    assert c.get(f"/v1/breaches/{bid}/drafts", headers=dpo).json()["notices"]
    assert c.get(f"/v1/breaches/{bid}/verify", headers=rev).json()["ok"]
    z = c.get(f"/v1/breaches/{bid}/bundle", headers=rev)
    assert z.status_code == 200 and z.headers["content-type"] == "application/zip"
    assert c.get("/v1/breaches/brc_nope", headers=dpo).status_code == 404
    assert c.post("/v1/breaches", headers=dpo, json={"stores": []}).status_code == 422
    assert c.get("/v1/breaches", headers=svc).status_code == 403


def test_cli_assess_list_drafts_export_verify(two, tmp_path, capsys):
    import yaml

    from dpdp_rights.cli import main
    f, *_ = two
    cfg = tmp_path / "cfg.yaml"
    cfg.write_text(yaml.safe_dump(f.config.model_dump(mode="json")))
    main(["-c", str(cfg), "breach", "assess", "--store", "records", "--by", "dpo:asha",
          "--aware-at", "2026-11-18T09:00:00+05:30"])
    out = json.loads(capsys.readouterr().out)
    bid = out["breach_id"]
    assert out["totals"]["affected"] == 2 and out["signed"]
    main(["-c", str(cfg), "breach", "drafts", bid, "--output", str(tmp_path / "d")])
    assert json.loads(capsys.readouterr().out)["notices"] == 2
    assert (tmp_path / "d" / "board-detailed.md").read_text().startswith("# Detailed report")
    main(["-c", str(cfg), "breach", "export", bid, "--output", str(tmp_path / "b.zip")])
    assert json.loads(capsys.readouterr().out)["signed"]
    main(["-c", str(cfg), "breach", "verify", bid])
    assert json.loads(capsys.readouterr().out)["ok"]
    with pytest.raises(SystemExit, match="refused: unknown breach"):
        main(["-c", str(cfg), "breach", "show", "brc_nope"])
