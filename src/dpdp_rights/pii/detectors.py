"""PII detectors. Pluggable and combined: regex (offline, India-aware, Indic scripts), Amazon Comprehend,
Amazon Bedrock Guardrails, Google Cloud DLP, Microsoft Presidio, Hugging Face NER (e.g. AI4Bharat IndicNER)
and an opt-in LLM detector. Results are merged and de-overlapped."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, Protocol


@dataclass(frozen=True)
class Entity:
    type: str
    start: int
    end: int
    text: str
    score: float = 1.0


class Detector(Protocol):
    def detect(self, text: str) -> list[Entity]: ...


# --------------------------------------------------------------------------
# Checksums
# --------------------------------------------------------------------------
_VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6], [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4], [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]
_VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2], [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]


def verhoeff_valid(number: str) -> bool:
    c = 0
    for i, ch in enumerate(reversed(number)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][int(ch)]]
    return c == 0


_VERHOEFF_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]


def verhoeff_check_digit(number: str) -> str:
    """Check digit for synthetic test data (e.g. fake Aadhaar numbers in demos/tests)."""
    c = 0
    for i, ch in enumerate(reversed(number)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[(i + 1) % 8][int(ch)]]
    return str(_VERHOEFF_INV[c])


def luhn_valid(number: str) -> bool:
    total, alt = 0, False
    for ch in reversed(number):
        d = int(ch)
        if alt:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
        alt = not alt
    return total % 10 == 0


# --------------------------------------------------------------------------
# Regex detector (offline; India-aware)
# --------------------------------------------------------------------------
# Indic digits (Devanagari, Bengali, Gurmukhi, Gujarati, Odia, Tamil, Telugu, Kannada, Malayalam) -> ASCII.
# One character maps to one character, so offsets are unchanged.
_INDIC_DIGITS = {cp + i: str(i) for cp in (0x0966, 0x09E6, 0x0A66, 0x0AE6, 0x0B66, 0x0BE6, 0x0C66, 0x0CE6, 0x0D66)
                 for i in range(10)}
_INDIC_DIGIT_TABLE = str.maketrans({chr(k): v for k, v in _INDIC_DIGITS.items()})

# Vehicle registration state / UT codes (incl. legacy codes still on older plates).
_RTO_STATES = ("AN|AP|AR|AS|BR|CG|CH|DD|DL|DN|GA|GJ|HP|HR|JH|JK|KA|KL|LA|LD|MH|ML|MN|MP|MZ|NL|OD|OR|PB|PY|"
               "RJ|SK|TN|TR|TS|UK|UA|UP|WB")

_INDIC = r"\u0900-\u0963\u0966-\u0DFF"   # Indic script blocks incl. vowel signs, minus the danda punctuation (। ॥)
_INDIC_WORD = rf"[{_INDIC}]+"
# "my name is" in Indian languages: Hindi, Marathi, Bengali, Gujarati, Punjabi, Tamil, Telugu, Kannada, Malayalam
_INDIC_NAME_CUES = ("मेरा नाम|मेरी नाम|माझे नाव|माझं नाव|नाम|नाव|আমার নাম|নাম|મારું નામ|નામ|ਮੇਰਾ ਨਾਮ|ਨਾਮ|"
                    "என் பெயர்|பெயர்|నా పేరు|పేరు|ನನ್ನ ಹೆಸರು|ಹೆಸರು|എന്റെ പേര്|പേര്")
# Words that end the sentence rather than belong to the name ("is", "am", ...)
_INDIC_STOP = {"है", "हैं", "हूँ", "हूं", "आहे", "হল", "হলো", "আছে", "છે", "ਹੈ", "ஆகும்", "ఉంది", "ಆಗಿದೆ", "ആണ്", "और", "आणि"}


def _gstin_valid(g: str) -> bool:
    chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    total = 0
    for i, ch in enumerate(g[:14]):
        v = chars.index(ch) * (2 if i % 2 else 1)
        total += v // 36 + v % 36
    return chars[(36 - total % 36) % 36] == g[14]


class RegexDetector:
    """Deterministic detector for identifiers common in Indian data, in any Indian script's digits.

    Structured identifiers: email, UPI ID, Aadhaar (Verhoeff), card (Luhn), PAN, mobile numbers, vehicle
    registration, GSTIN (checksum), ABHA number, driving licence; voter ID, passport and bank account
    numbers only next to a context word. Names: simple cues in English, Hinglish and nine Indian
    languages. Addresses: only after a cue word and ending in a PIN code. Anything else (names without a
    cue, free-text disclosures) needs an NER, cloud or LLM detector alongside this one.
    """

    PATTERNS: list[tuple[str, re.Pattern[str]]] = [
        ("EMAIL", re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)+\b")),
        ("UPI_ID", re.compile(r"\b[A-Za-z0-9.\-_]{2,256}@(?:ok)?[a-zA-Z]{2,64}\b(?!\.[A-Za-z0-9])")),  # not an email domain
        ("AADHAAR", re.compile(r"(?<!\d)[2-9]\d{3}[ \-]?\d{4}[ \-]?\d{4}(?!\d)")),
        ("CARD_NUMBER", re.compile(r"(?<!\d)(?:\d[ \-]?){13,19}(?!\d)")),
        ("PAN", re.compile(r"\b[A-Z]{3}[ABCFGHLJPT][A-Z]\d{4}[A-Z]\b")),
        ("PHONE_IN", re.compile(r"(?<![\d+])(?:\+91[\-\s]?|0)?[6-9]\d{4}[\-\s]?\d{5}(?!\d)")),
        ("ABHA_NUMBER", re.compile(r"(?<!\d)\d{2}-\d{4}-\d{4}-\d{4}(?!\d)")),
        ("GSTIN", re.compile(r"\b\d{2}[A-Z]{5}\d{4}[A-Z][1-9A-Z]Z[0-9A-Z]\b")),
        ("VEHICLE_REG", re.compile(rf"\b(?:(?:{_RTO_STATES})[ \-]?\d{{1,2}}[ \-]?[A-Z]{{0,3}}[ \-]?\d{{4}}"
                                   r"|\d{2}[ \-]?BH[ \-]?\d{4}[ \-]?[A-Z]{1,2})\b")),
        ("DRIVING_LICENCE", re.compile(rf"\b(?:{_RTO_STATES})[ \-]?\d{{2}}[ \-]?(?:19|20)\d{{2}}[ \-]?\d{{7}}\b")),
    ]
    # Only reported when a context word appears shortly before the number.
    CONTEXT_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
        ("VOTER_ID", re.compile(r"(?i:voter|epic|मतदाता)\D{0,25}?\b([A-Z]{3}\d{7})\b")),
        ("PASSPORT", re.compile(r"(?i:passport|पासपोर्ट)\D{0,25}?\b([A-PR-WY][1-9]\d\s?\d{4}[1-9])\b")),
        ("BANK_ACCOUNT", re.compile(r"(?i:a/c|acct|account(?:\s+(?:no|number))?|खाता(?:\s+संख्या)?)\D{0,15}?(?<!\d)(\d{9,18})(?!\d)")),
    ]
    NAME_CUE = re.compile(
        r"\b(?i:my name is|i am|i'm|this is|name:)\s+((?:[A-Z][a-z]+)(?:\s+[A-Z][a-z]+){0,2})"
    )
    # Hinglish: "mera naam priya sharma hai", often all lower case, so bounded by "hai"
    HINGLISH_NAME_CUE = re.compile(r"(?i)\b(?:mera|meri)\s+na+a?m\s+([a-z]+(?:\s+[a-z]+){0,2}?)\s+(?:hai|h|hain)\b")
    INDIC_NAME_CUE = re.compile(rf"(?:{_INDIC_NAME_CUES})\s*[:：]?\s*({_INDIC_WORD}(?:\s+{_INDIC_WORD}){{0,2}})")
    ADDRESS_CUE = re.compile(
        r"(?i:address|addr\.?|residing at|resident of|lives at|staying at|पता|पत्ता|ঠিকানা|முகவரி|చిరునామా|ವಿಳಾಸ|સરનામું)"
        r"\s*(?:is|:|-)?\s*(.{5,160}?(?<!\d)[1-9]\d{2}\s?\d{3}(?!\d))"
    )

    def __init__(self, detect_names: bool = True):
        self.detect_names = detect_names

    def detect(self, text: str) -> list[Entity]:
        norm = text.translate(_INDIC_DIGIT_TABLE)   # same length: offsets map 1:1 back to `text`
        out: list[Entity] = []
        for etype, pat in self.PATTERNS:
            for m in pat.finditer(norm):
                raw = m.group(0)
                digits = re.sub(r"\D", "", raw)
                if etype == "AADHAAR" and not verhoeff_valid(digits):
                    continue
                if etype == "CARD_NUMBER" and not (13 <= len(digits) <= 19 and luhn_valid(digits)):
                    continue
                if etype == "GSTIN" and not _gstin_valid(raw):
                    continue
                out.append(Entity(etype, m.start(), m.end(), text[m.start():m.end()]))
        for etype, pat in self.CONTEXT_PATTERNS:
            for m in pat.finditer(norm):
                out.append(Entity(etype, m.start(1), m.end(1), text[m.start(1):m.end(1)], 0.85))
        for m in self.ADDRESS_CUE.finditer(norm):
            out.append(Entity("ADDRESS", m.start(1), m.end(1), text[m.start(1):m.end(1)], 0.75))
        if self.detect_names:
            for pat in (self.NAME_CUE, self.HINGLISH_NAME_CUE):
                for m in pat.finditer(text):
                    out.append(Entity("NAME", m.start(1), m.end(1), m.group(1), 0.7))
            for m in self.INDIC_NAME_CUE.finditer(text):
                words = m.group(1).split()
                while words and words[-1] in _INDIC_STOP:
                    words.pop()
                if words:
                    name = " ".join(words)
                    out.append(Entity("NAME", m.start(1), m.start(1) + len(name), name, 0.7))
        return out


# --------------------------------------------------------------------------
# Cloud-native detectors
# --------------------------------------------------------------------------
_COMPREHEND_MAP = {
    "NAME": "NAME", "EMAIL": "EMAIL", "PHONE": "PHONE", "ADDRESS": "ADDRESS",
    "CREDIT_DEBIT_NUMBER": "CARD_NUMBER", "BANK_ACCOUNT_NUMBER": "BANK_ACCOUNT",
    "IN_AADHAAR": "AADHAAR", "IN_PERMANENT_ACCOUNT_NUMBER": "PAN",
    "IN_VOTER_NUMBER": "VOTER_ID", "IN_NREGA": "NREGA", "DATE_TIME": None,
}


class ComprehendDetector:
    """Amazon Comprehend DetectPiiEntities."""

    def __init__(self, region: str | None = None, min_score: float = 0.8, client=None):
        import boto3

        self.client = client or boto3.client("comprehend", region_name=region)
        self.min_score = min_score

    def detect(self, text: str) -> list[Entity]:
        if not text.strip():
            return []
        resp = self.client.detect_pii_entities(Text=text[:100_000], LanguageCode="en")
        out = []
        for e in resp.get("Entities", []):
            etype = _COMPREHEND_MAP.get(e["Type"], e["Type"])
            if etype is None or e["Score"] < self.min_score:
                continue
            s, t = e["BeginOffset"], e["EndOffset"]
            out.append(Entity(etype, s, t, text[s:t], e["Score"]))
        return out


class BedrockGuardrailDetector:
    """Amazon Bedrock Guardrails ApplyGuardrail (sensitive information filter).

    Lets partners reuse the PII entity + regex config already defined in a
    guardrail that fronts their Bedrock / AgentCore agents.
    """

    def __init__(self, guardrail_id: str, version: str = "DRAFT", region: str | None = None, client=None):
        import boto3

        self.client = client or boto3.client("bedrock-runtime", region_name=region)
        self.guardrail_id, self.version = guardrail_id, version

    def detect(self, text: str) -> list[Entity]:
        resp = self.client.apply_guardrail(
            guardrailIdentifier=self.guardrail_id,
            guardrailVersion=self.version,
            source="INPUT",
            content=[{"text": {"text": text}}],
        )
        out: list[Entity] = []
        for a in resp.get("assessments", []):
            sip = a.get("sensitiveInformationPolicy", {})
            matches = [(p["type"], p["match"]) for p in sip.get("piiEntities", [])]
            matches += [(r.get("name", "CUSTOM"), r["match"]) for r in sip.get("regexes", [])]
            for etype, match in matches:
                start = 0
                while (idx := text.find(match, start)) != -1:
                    out.append(Entity(_COMPREHEND_MAP.get(etype, etype) or etype, idx, idx + len(match), match))
                    start = idx + len(match)
        return out


class GcpDlpDetector:
    """Google Cloud Sensitive Data Protection (DLP) inspect_content."""

    INFO_TYPES = [
        "PERSON_NAME", "EMAIL_ADDRESS", "PHONE_NUMBER", "STREET_ADDRESS",
        "CREDIT_CARD_NUMBER", "INDIA_AADHAAR_INDIVIDUAL", "INDIA_PAN_INDIVIDUAL",
        "INDIA_GST_INDIVIDUAL", "INDIA_PASSPORT",
    ]
    _MAP = {
        "PERSON_NAME": "NAME", "EMAIL_ADDRESS": "EMAIL", "PHONE_NUMBER": "PHONE",
        "STREET_ADDRESS": "ADDRESS", "CREDIT_CARD_NUMBER": "CARD_NUMBER",
        "INDIA_AADHAAR_INDIVIDUAL": "AADHAAR", "INDIA_PAN_INDIVIDUAL": "PAN",
        "INDIA_PASSPORT": "PASSPORT",
    }

    def __init__(self, project: str, client=None):
        from google.cloud import dlp_v2  # type: ignore

        self.client = client or dlp_v2.DlpServiceClient()
        self.parent = f"projects/{project}/locations/global"

    def detect(self, text: str) -> list[Entity]:
        resp = self.client.inspect_content(
            request={
                "parent": self.parent,
                "inspect_config": {
                    "info_types": [{"name": n} for n in self.INFO_TYPES],
                    "include_quote": True,
                    "min_likelihood": "LIKELY",
                },
                "item": {"value": text},
            }
        )
        out = []
        for f in resp.result.findings:
            r = f.location.codepoint_range
            name = f.info_type.name
            out.append(Entity(self._MAP.get(name, name), r.start, r.end, text[r.start:r.end]))
        return out


# --------------------------------------------------------------------------
# Open-source NER and model-based detectors
# --------------------------------------------------------------------------
_PRESIDIO_MAP = {
    "PERSON": "NAME", "EMAIL_ADDRESS": "EMAIL", "PHONE_NUMBER": "PHONE", "CREDIT_CARD": "CARD_NUMBER",
    "IBAN_CODE": "BANK_ACCOUNT", "IP_ADDRESS": "IP_ADDRESS", "LOCATION": "ADDRESS",
    "IN_AADHAAR": "AADHAAR", "IN_PAN": "PAN", "IN_PASSPORT": "PASSPORT", "IN_VOTER": "VOTER_ID",
    "IN_VEHICLE_REGISTRATION": "VEHICLE_REG", "IN_GSTIN": "GSTIN",
}
_PRESIDIO_DEFAULT = ["PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD", "IBAN_CODE", "IP_ADDRESS",
                     "IN_AADHAAR", "IN_PAN", "IN_PASSPORT", "IN_VOTER", "IN_VEHICLE_REGISTRATION", "IN_GSTIN"]


class PresidioDetector:
    """Microsoft Presidio Analyzer, with its India recognisers loaded.

    Runs in-process, so text never leaves your environment. The NER quality depends on the NLP model:
    ``en_core_web_lg`` (spaCy) or a transformers model is recommended over ``en_core_web_sm``.
    LOCATION is off by default (it tags city names, which are rarely personal on their own); add it to
    ``entities`` to tokenise locations as ADDRESS.
    """

    def __init__(self, language: str = "en", spacy_model: str = "en_core_web_lg",
                 entities: list[str] | None = None, min_score: float = 0.6,
                 nlp_configuration: dict | None = None, analyzer=None):
        self.language, self.min_score = language, min_score
        self.entities = entities or list(_PRESIDIO_DEFAULT)
        if analyzer is None:
            from presidio_analyzer import AnalyzerEngine  # type: ignore
            from presidio_analyzer import predefined_recognizers as pr  # type: ignore
            from presidio_analyzer.nlp_engine import NlpEngineProvider  # type: ignore

            conf = nlp_configuration or {"nlp_engine_name": "spacy",
                                         "models": [{"lang_code": language, "model_name": spacy_model}]}
            analyzer = AnalyzerEngine(nlp_engine=NlpEngineProvider(nlp_configuration=conf).create_engine(),
                                      supported_languages=[language])
            for name in ("InAadhaarRecognizer", "InPanRecognizer", "InPassportRecognizer", "InVoterRecognizer",
                         "InVehicleRegistrationRecognizer", "InGstinRecognizer"):
                cls = getattr(pr, name, None)
                if cls is not None:
                    analyzer.registry.add_recognizer(cls(supported_language=language))
        self.analyzer = analyzer

    def detect(self, text: str) -> list[Entity]:
        if not text.strip():
            return []
        out = []
        for r in self.analyzer.analyze(text=text, language=self.language, entities=self.entities):
            if r.score < self.min_score:
                continue
            out.append(Entity(_PRESIDIO_MAP.get(r.entity_type, r.entity_type), r.start, r.end,
                              text[r.start:r.end], float(r.score)))
        return out


class TransformersNerDetector:
    """Any Hugging Face token-classification model, run locally.

    The default, ``ai4bharat/IndicNER``, recognises person, location and organisation names in 11 Indian
    languages. Text stays in your environment; the model is downloaded once (or loaded from ``model``
    as a local path, e.g. baked into your image).
    """

    LABELS = {"PER": "NAME", "PERSON": "NAME", "LOC": "ADDRESS", "LOCATION": "ADDRESS"}

    def __init__(self, model: str = "ai4bharat/IndicNER", include_locations: bool = False,
                 min_score: float = 0.7, device: int | str = -1, pipeline=None):
        self.min_score, self.include_locations = min_score, include_locations
        if pipeline is None:
            from transformers import pipeline as hf_pipeline  # type: ignore

            pipeline = hf_pipeline("token-classification", model=model, aggregation_strategy="simple",
                                   device=device)
        self.pipeline = pipeline

    def detect(self, text: str) -> list[Entity]:
        if not text.strip():
            return []
        out = []
        for r in self.pipeline(text):
            label = str(r.get("entity_group") or r.get("entity", "")).split("-")[-1].upper()
            etype = self.LABELS.get(label)
            if etype is None or (etype == "ADDRESS" and not self.include_locations):
                continue
            if float(r.get("score", 0)) < self.min_score:
                continue
            s, e = int(r["start"]), int(r["end"])
            out.append(Entity(etype, s, e, text[s:e], float(r["score"])))
        return out


_LLM_TYPES = ("NAME", "ADDRESS", "EMAIL", "PHONE", "AADHAAR", "PAN", "PASSPORT", "VOTER_ID", "DRIVING_LICENCE",
              "VEHICLE_REG", "BANK_ACCOUNT", "CARD_NUMBER", "UPI_ID", "DATE_OF_BIRTH", "HEALTH", "OTHER_ID")
_LLM_SYSTEM = (
    "You find personal data in text for a privacy tokeniser. The text may be in English, any Indian language "
    "or script, or transliterated (e.g. Hinglish). Return ONLY a JSON array of objects "
    '{"type": <one of ' + ", ".join(_LLM_TYPES) + '>, "text": <exact substring copied from the input>}. '
    "Include names of people, postal addresses, identifiers, dates of birth, and statements about a person's "
    "health. Copy each value exactly as it appears, character for character. Skip anything already shaped "
    "like <TYPE_xxxxxxxxxxxx>. Return [] if there is nothing."
)


class LLMDetector:
    """Uses a language model to find personal data that rules and NER miss: names without cue words,
    addresses, Indian languages, transliteration, free-text disclosures.

    **Privacy trade-off:** the raw text is sent to this model *before* tokenisation. Configure a separate
    model you control for this (e.g. Bedrock in your region with invocation logging off, or a self-hosted
    model), never a third-party endpoint that retains prompts. Off unless listed in ``pii.detectors``.
    """

    def __init__(self, provider, max_chars: int = 6000, score: float = 0.8):
        self.provider, self.max_chars, self.score = provider, max_chars, score

    def detect(self, text: str) -> list[Entity]:
        out: list[Entity] = []
        for offset in range(0, len(text), self.max_chars):
            chunk = text[offset:offset + self.max_chars]
            if chunk.strip():
                out.extend(self._detect_chunk(chunk, offset))
        return out

    def _detect_chunk(self, chunk: str, offset: int) -> list[Entity]:
        import json

        try:
            raw = self.provider.generate(chunk, system=_LLM_SYSTEM).text
            start, end = raw.find("["), raw.rfind("]")
            items = json.loads(raw[start:end + 1]) if start != -1 and end > start else []
        except Exception:  # noqa: BLE001 - a detector failure must not block processing; other detectors still run
            return []
        out = []
        for it in items if isinstance(items, list) else []:
            if not isinstance(it, dict):
                continue
            value, etype = str(it.get("text") or "").strip(), str(it.get("type") or "OTHER_ID").upper()
            if len(value) < 2 or TOKEN_FULL.fullmatch(value):
                continue
            pos = 0
            while (idx := chunk.find(value, pos)) != -1:     # only exact substrings: never trust model offsets
                out.append(Entity(etype if etype in _LLM_TYPES else "OTHER_ID", offset + idx,
                                  offset + idx + len(value), value, self.score))
                pos = idx + len(value)
        return out


TOKEN_FULL = re.compile(r"<[A-Z][A-Z0-9_]*?_[0-9a-f]{12}>")


# --------------------------------------------------------------------------
class CompositeDetector:
    def __init__(self, detectors: Iterable[Detector]):
        self.detectors = list(detectors)

    def detect(self, text: str) -> list[Entity]:
        found: list[Entity] = []
        for d in self.detectors:
            found.extend(d.detect(text))
        return merge_entities(found)


def merge_entities(entities: list[Entity]) -> list[Entity]:
    """Drop overlaps, preferring the longer span, then the higher score."""
    ranked = sorted(entities, key=lambda e: (-(e.end - e.start), -e.score, e.start))
    kept: list[Entity] = []
    for e in ranked:
        if all(e.end <= k.start or e.start >= k.end for k in kept):
            kept.append(e)
    return sorted(kept, key=lambda e: e.start)


def build_detector(cfg, llm_provider=None) -> CompositeDetector:
    dets: list[Detector] = []
    for name in cfg.detectors:
        if name == "regex":
            dets.append(RegexDetector(detect_names=cfg.detect_names))
        elif name == "aws_comprehend":
            dets.append(ComprehendDetector(region=cfg.region, min_score=cfg.min_score))
        elif name == "bedrock_guardrail":
            if not cfg.guardrail_id:
                raise ValueError("pii.guardrail_id is required for bedrock_guardrail")
            dets.append(BedrockGuardrailDetector(cfg.guardrail_id, cfg.guardrail_version, cfg.region))
        elif name == "gcp_dlp":
            if not cfg.project:
                raise ValueError("pii.project is required for gcp_dlp")
            dets.append(GcpDlpDetector(cfg.project))
        elif name == "presidio":
            dets.append(PresidioDetector(**cfg.presidio))
        elif name == "transformers_ner":
            dets.append(TransformersNerDetector(**cfg.transformers_ner))
        elif name == "llm":
            if llm_provider is None:
                raise ValueError("pii.llm (a provider config) is required for the llm detector")
            dets.append(LLMDetector(llm_provider, **cfg.llm_options))
        else:
            raise ValueError(f"Unknown PII detector {name}")
    return CompositeDetector(dets)
