"""PII benchmark, the NER sidecar and the remote_ner detector (docs/pii-benchmark.md)."""
import io
import json
import urllib.error

import pytest
from fastapi.testclient import TestClient

from dpdp_rights.pii import benchmark as bm
from dpdp_rights.pii.detectors import CompositeDetector, Entity, RegexDetector, build_detector
from dpdp_rights.pii.ner_server import RemoteNerDetector, create_ner_app


def test_built_in_set_is_reproducible_and_shipped():
    shipped = bm.BUILTIN.read_text(encoding="utf-8")
    assert shipped == "".join(r.to_json() + "\n" for r in bm.build_builtin()), \
        "regenerate with: python -m dpdp_rights.pii.benchmark"


def test_built_in_set_covers_languages_scripts_and_hard_cases():
    recs = bm.load()
    langs = {r.lang for r in recs}
    assert {"en", "hi-Latn", "hi", "mr", "ta-Latn", "ta", "te-Latn", "te", "bn", "kn"} <= langs
    tags = {t for r in recs for t in r.tags}
    assert {"negative", "uncued_name", "uncued_address", "romanised_cue", "native_digits"} <= tags
    types = {e["type"] for r in recs for e in r.entities}
    assert {"NAME", "PHONE_IN", "EMAIL", "AADHAAR", "PAN", "UPI_ID", "CARD_NUMBER", "VEHICLE_REG", "BANK_ACCOUNT",
            "ADDRESS"} <= types
    for r in recs:                                     # every label points at real text, no overlaps
        spans = sorted((e["start"], e["end"]) for e in r.entities)
        assert all(a[1] <= b[0] for a, b in zip(spans, spans[1:], strict=False))
        assert all(r.text[s:e].strip() == r.text[s:e] and r.text[s:e] for s, e in spans)


def test_regex_baseline_is_what_the_docs_say():
    rep = bm.benchmark(bm.load(), CompositeDetector([RegexDetector()]))
    t = rep["combined"]["by_type"]
    for k in ("AADHAAR", "PAN", "EMAIL", "UPI_ID", "CARD_NUMBER", "VEHICLE_REG", "BANK_ACCOUNT"):
        assert t[k]["recall"] == 1.0 and t[k]["precision"] == 1.0, k
    assert t["PHONE_IN"]["recall"] == 1.0 and t["PHONE_IN"]["fp"] == 3      # claim numbers shaped like phones
    assert t["NAME"]["recall"] < 0.4 and t["NAME"]["precision"] == 1.0
    tags = rep["combined"]["by_tag"]
    assert tags["uncued_name"]["recall"] == 0.0 and tags["romanised_cue"]["recall"] == 0.0
    assert tags["native_digits"]["recall"] == 1.0 and tags["uncued_address"]["recall"] == 0.0
    assert rep["combined"]["negatives"] == {"records": 57, "flagged": 3}


def test_a_context_named_account_number_is_not_an_aadhaar_even_if_it_passes_verhoeff():
    d = RegexDetector()
    assert [(e.type, e.text) for e in d.detect("refund to account 887470005117 please")] == \
        [("BANK_ACCOUNT", "887470005117")]
    assert [e.type for e in d.detect("my aadhaar for the account is 887470005117")] == ["AADHAAR"]


def test_matching_overlap_versus_exact_and_false_positives():
    recs = [bm.Record("1", "en", "call Priya Sharma now", [{"type": "NAME", "start": 5, "end": 17}])]

    class Partial:
        detectors = []

        def detect(self, text):
            return [Entity("PERSON", 5, 15, "Priya Shar"), Entity("EMAIL", 0, 4, "call")]
    loose = bm.benchmark(recs, Partial())["combined"]["by_type"]
    assert loose["NAME"]["tp"] == 1 and loose["EMAIL"]["fp"] == 1        # PERSON counts as NAME; 10 of 12 chars
    exact = bm.benchmark(recs, Partial(), mode="exact")["combined"]["by_type"]
    assert exact["NAME"]["tp"] == 0 and exact["NAME"]["fn"] == 1


def test_thresholds_and_markdown():
    rep = bm.benchmark(bm.load(), CompositeDetector([RegexDetector()]))
    assert bm.check_thresholds(rep, {"PHONE_IN": 0.95, "ALL": 0.5}, {"PAN": 0.99}) == []
    fails = bm.check_thresholds(rep, {"NAME": 0.8, "OTHER_ID": 0.5}, {})
    assert fails[0].startswith("NAME recall 0.32") and "OTHER_ID recall n/a" in fails[1]
    md = bm.markdown(rep)
    assert "| NAME |" in md and "Hard cases" in md and "Look-alike records flagged: 3 of 57" in md


def test_label_studio_exports_load_with_a_label_map(tmp_path):
    p = tmp_path / "ls.json"
    p.write_text(json.dumps([
        {"id": 7, "data": {"text": "Mera naam Asha hai", "lang": "hi-Latn"}, "annotations": [{"result": [
            {"value": {"start": 10, "end": 14, "text": "Asha", "labels": ["PERSON"]}}]}]},
        {"id": 8, "data": {"text": "nothing"}, "annotations": [{"was_cancelled": True, "result": []}]}]))
    recs = bm.from_label_studio(p, {"PERSON": "NAME"})
    assert recs[0].entities == [{"type": "NAME", "start": 10, "end": 14}] and recs[0].lang == "hi-Latn"
    assert recs[1].entities == []


def test_labels_outside_the_text_are_refused(tmp_path):
    p = tmp_path / "bad.jsonl"
    p.write_text(json.dumps({"text": "abc", "entities": [{"type": "NAME", "start": 1, "end": 9}]}) + "\n")
    with pytest.raises(ValueError, match="outside the text"):
        bm.load(p)


# ---- NER sidecar and remote_ner --------------------------------------------------------------------------------------
class _FakeNer:
    """Finds the names it is told about, like a model would."""
    def __init__(self, names):
        self.names = names

    def detect(self, text):
        out = []
        for n in self.names:
            i = text.find(n)
            if i >= 0:
                out.append(Entity("NAME", i, i + len(n), n, 0.93))
        return out


def _opener_for(client):
    def opener(req, timeout):
        r = client.post(req.full_url.replace("http://127.0.0.1:8081", ""), content=req.data,
                        headers={"Content-Type": "application/json"})
        if r.status_code >= 400:
            raise urllib.error.HTTPError(req.full_url, r.status_code, r.text, {}, None)
        return io.BytesIO(r.content)
    return opener


def test_sidecar_api_and_remote_detector_round_trip():
    c = TestClient(create_ner_app(_FakeNer(["प्रिया शर्मा", "Rahul Verma"]), "fake/indic"))
    assert c.get("/healthz").json() == {"ok": True, "model": "fake/indic"}
    r = c.post("/v1/ner", json={"texts": ["कल प्रिया शर्मा ने शिकायत की", "nobody"]}).json()
    assert r["entities"][0] == [{"type": "NAME", "start": 3, "end": 15, "score": 0.93}] and r["entities"][1] == []
    assert c.post("/v1/ner", json={"texts": ["x"] * 65}).status_code == 413
    assert c.post("/v1/ner", json={"texts": ["x" * 20001]}).status_code == 413
    assert c.get("/docs").status_code == 404                      # nothing extra exposed
    det = RemoteNerDetector(opener=_opener_for(c))
    assert [(e.type, e.text) for e in det.detect("Spoke to Rahul Verma today")] == [("NAME", "Rahul Verma")]


def test_remote_ner_lifts_name_recall_in_the_benchmark():
    names = sorted({r.text[e["start"]:e["end"]] for r in bm.load() for e in r.entities if e["type"] == "NAME"})
    c = TestClient(create_ner_app(_FakeNer(names), "fake"))
    composite = CompositeDetector([RegexDetector(), RemoteNerDetector(opener=_opener_for(c))])
    rep = bm.benchmark(bm.load(), composite)
    assert rep["combined"]["by_type"]["NAME"]["recall"] == 1.0
    assert set(rep["by_detector"]) == {"RegexDetector", "RemoteNerDetector"}


def test_remote_ner_fails_closed_by_default_or_skips_when_asked():
    def down(req, timeout):
        raise urllib.error.URLError("connection refused")
    with pytest.raises(RuntimeError, match="unavailable"):
        RemoteNerDetector(opener=down).detect("Rahul Verma")
    skip = RemoteNerDetector(opener=down, on_error="skip")
    assert skip.detect("Rahul Verma") == [] and skip.skipped == 1
    with pytest.raises(ValueError):
        RemoteNerDetector(on_error="ignore")


def test_remote_ner_is_a_configurable_detector():
    from dpdp_rights.core.config import PIIConfig

    comp = build_detector(PIIConfig(detectors=["regex", "remote_ner"],
                                    remote_ner={"url": "http://127.0.0.1:9999", "on_error": "skip"}))
    assert isinstance(comp.detectors[1], RemoteNerDetector) and comp.detectors[1].url == "http://127.0.0.1:9999"


def test_cli_benchmark_gates_on_thresholds(capsys, tmp_path):
    from dpdp_rights.cli import main

    with pytest.raises(SystemExit) as e:
        main(["-c", "config/dpdp.local.yaml", "pii-benchmark", "--min-recall", "PHONE_IN=0.95"])
    assert e.value.code == 0 and "| PHONE_IN |" in capsys.readouterr().out
    with pytest.raises(SystemExit) as e:
        main(["-c", "config/dpdp.local.yaml", "pii-benchmark", "--min-recall", "NAME=0.8", "--format", "json"])
    out = capsys.readouterr()
    assert e.value.code == 1 and json.loads(out.out)["threshold_failures"] and "below threshold" in out.err
