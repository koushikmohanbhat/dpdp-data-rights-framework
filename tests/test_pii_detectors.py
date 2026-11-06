"""Presidio, Hugging Face NER and LLM detectors (with fakes; a real Presidio run when it is installed)."""
import json
from types import SimpleNamespace

import pytest

from dpdp_rights.core.config import FrameworkConfig
from dpdp_rights.pii.detectors import (
    CompositeDetector,
    LLMDetector,
    PresidioDetector,
    RegexDetector,
    TransformersNerDetector,
)
from dpdp_rights.security.guardrails import production_issues


class FakeAnalyzer:
    def __init__(self, results):
        self.results = results

    def analyze(self, text, language, entities):
        return [SimpleNamespace(entity_type=t, start=s, end=e, score=sc) for t, s, e, sc in self.results
                if t in entities]


def test_presidio_maps_types_and_filters():
    text = "Priya Sharma lives in Pune"
    d = PresidioDetector(analyzer=FakeAnalyzer([("PERSON", 0, 12, 0.85), ("LOCATION", 22, 26, 0.85),
                                                ("PERSON", 13, 18, 0.3)]))
    assert [(e.type, e.text) for e in d.detect(text)] == [("NAME", "Priya Sharma")]   # LOCATION off, low score dropped
    d = PresidioDetector(entities=["PERSON", "LOCATION"], analyzer=FakeAnalyzer([("LOCATION", 22, 26, 0.85)]))
    assert [(e.type, e.text) for e in d.detect(text)] == [("ADDRESS", "Pune")]


def test_presidio_real_engine_when_installed():
    pytest.importorskip("presidio_analyzer")
    spacy = pytest.importorskip("spacy")
    if not spacy.util.is_package("en_core_web_sm"):
        pytest.skip("spaCy model en_core_web_sm not installed")
    d = PresidioDetector(spacy_model="en_core_web_sm")
    found = {(e.type, e.text) for e in d.detect("Please call Priya Sharma about PAN ABCPS1234K")}
    assert ("PAN", "ABCPS1234K") in found
    assert any(t == "NAME" and "Priya" in v for t, v in found)


def test_transformers_ner_maps_indic_labels():
    text = "मेरी बहन सुनीता पुणे में रहती है"
    s1, s2 = text.index("सुनीता"), text.index("पुणे")
    fake = lambda t: [{"entity_group": "PER", "start": s1, "end": s1 + 6, "score": 0.97},       # noqa: E731
                      {"entity_group": "LOC", "start": s2, "end": s2 + 4, "score": 0.95},
                      {"entity_group": "ORG", "start": 0, "end": 4, "score": 0.99}]
    assert [(e.type, e.text) for e in TransformersNerDetector(pipeline=fake).detect(text)] == [("NAME", "सुनीता")]
    with_loc = TransformersNerDetector(pipeline=fake, include_locations=True).detect(text)
    assert ("ADDRESS", "पुणे") in [(e.type, e.text) for e in with_loc]


class FakeLLM:
    def __init__(self, reply):
        self.reply, self.calls = reply, []

    def generate(self, prompt, system=None, **kw):
        self.calls.append(prompt)
        return SimpleNamespace(text=self.reply)


def test_llm_detector_finds_exact_substrings_only():
    text = "mera naam priya hai aur main 12 Shanti Nagar, Pune mein rehti hoon. Mujhe diabetes hai."
    reply = "Here you go:\n" + json.dumps([
        {"type": "NAME", "text": "priya"},
        {"type": "ADDRESS", "text": "12 Shanti Nagar, Pune"},
        {"type": "HEALTH", "text": "Mujhe diabetes hai"},
        {"type": "NAME", "text": "Rahul"},                 # hallucinated: not in the text, must be ignored
        {"type": "EMAIL", "text": "<EMAIL_0123456789ab>"},  # already a token
    ])
    got = [(e.type, e.text) for e in LLMDetector(FakeLLM(reply)).detect(text)]
    assert got == [("NAME", "priya"), ("ADDRESS", "12 Shanti Nagar, Pune"), ("HEALTH", "Mujhe diabetes hai")]


def test_llm_detector_failure_does_not_block_other_detectors():
    composite = CompositeDetector([RegexDetector(), LLMDetector(FakeLLM("not json at all"))])
    assert [e.type for e in composite.detect("mail priya@example.in")] == ["EMAIL"]


def test_llm_detector_chunks_long_text_with_correct_offsets():
    llm = FakeLLM(json.dumps([{"type": "NAME", "text": "Asha"}]))
    text = "x" * 50 + " Asha " + "y" * 50
    ents = LLMDetector(llm, max_chars=40).detect(text)
    assert len(llm.calls) == 3 and [text[e.start:e.end] for e in ents] == ["Asha"]


def _prod(**pii):
    return FrameworkConfig.model_validate({
        "environment": "production",
        "provider": {"type": "bedrock", "model": "m1"},
        "pii": {"detectors": ["regex", "llm"], **pii},
    })


def test_guardrails_on_llm_detector():
    msgs = [m for _, m in production_issues(_prod())]
    assert any("pii.llm (the detection model) is not configured" in m for m in msgs)
    msgs = [m for _, m in production_issues(_prod(llm={"type": "openai", "model": "x"}))]
    assert any("sends raw text" in m for m in msgs) and any("leaves your cloud" in m for m in msgs)
    msgs = [m for _, m in production_issues(_prod(llm={"type": "bedrock", "model": "m1"}))]
    assert any("same model as provider" in m for m in msgs)
    assert not any("no NER detector" in m for m in msgs)
