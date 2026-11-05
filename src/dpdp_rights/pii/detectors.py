"""PII detectors. Pluggable: regex (offline, India-aware), Amazon Comprehend,
Amazon Bedrock Guardrails, Google Cloud DLP. Results are merged."""
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
class RegexDetector:
    """Deterministic detector for structured identifiers common in Indian data.

    Names and addresses are only caught by simple cues ("my name is ...");
    use Comprehend / Guardrails / DLP alongside it in production.
    """

    PATTERNS: list[tuple[str, re.Pattern[str]]] = [
        ("EMAIL", re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)+\b")),
        ("UPI_ID", re.compile(r"\b[A-Za-z0-9.\-_]{2,256}@(?:ok)?[a-zA-Z]{2,64}\b(?!\.)")),
        ("AADHAAR", re.compile(r"(?<!\d)[2-9]\d{3}[ \-]?\d{4}[ \-]?\d{4}(?!\d)")),
        ("CARD_NUMBER", re.compile(r"(?<!\d)(?:\d[ \-]?){13,19}(?!\d)")),
        ("PAN", re.compile(r"\b[A-Z]{3}[ABCFGHLJPT][A-Z]\d{4}[A-Z]\b")),
        ("PHONE_IN", re.compile(r"(?<![\d+])(?:\+91[\-\s]?|0)?[6-9]\d{4}[\-\s]?\d{5}(?!\d)")),
    ]
    NAME_CUE = re.compile(
        r"\b(?i:my name is|i am|i'm|this is|name:)\s+((?:[A-Z][a-z]+)(?:\s+[A-Z][a-z]+){0,2})"
    )

    def __init__(self, detect_names: bool = True):
        self.detect_names = detect_names

    def detect(self, text: str) -> list[Entity]:
        out: list[Entity] = []
        for etype, pat in self.PATTERNS:
            for m in pat.finditer(text):
                raw = m.group(0)
                digits = re.sub(r"\D", "", raw)
                if etype == "AADHAAR" and not verhoeff_valid(digits):
                    continue
                if etype == "CARD_NUMBER" and not (13 <= len(digits) <= 19 and luhn_valid(digits)):
                    continue
                out.append(Entity(etype, m.start(), m.end(), raw))
        if self.detect_names:
            for m in self.NAME_CUE.finditer(text):
                out.append(Entity("NAME", m.start(1), m.end(1), m.group(1), 0.7))
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


def build_detector(cfg) -> CompositeDetector:
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
        else:
            raise ValueError(f"Unknown PII detector {name}")
    return CompositeDetector(dets)
