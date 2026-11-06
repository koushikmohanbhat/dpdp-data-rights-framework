"""PII detection benchmark: precision and recall per type, language and detector (docs/pii-benchmark.md).

Two kinds of labelled set:

- The **built-in set** ``indic-pii-v1``: synthetic and generated from templates with a fixed seed, so the offsets
  are exact and anyone can reproduce it. English; romanised code-mixed Hinglish, Tamil-English and
  Telugu-English; Hindi, Marathi, Tamil, Telugu, Bengali and Kannada in their own scripts, some with native
  digits; names with and without cue phrases; addresses with and without cue words; and look-alikes (OTPs, order,
  claim and ticket numbers, amounts) that must not be flagged. It says how detectors behave on these patterns, not
  how they will do on a client's traffic.
- **A client's labelled sample**: the same JSON Lines format, or a Label Studio export. That is the number to
  report to a client.

Matching: a labelled entity counts as found when a prediction of the same type overlaps at least half of it
(``--match exact`` needs the same span). Predictions that match nothing are false positives, whatever their type.
"""
from __future__ import annotations

import json
import random
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path

DATASET_VERSION = "indic-pii-v1"
BUILTIN = Path(__file__).parent / "benchmark_data" / f"{DATASET_VERSION}.jsonl"
SEED = 20261119

# Types other services report, mapped onto the framework's labels for comparison.
TYPE_ALIASES = {"PHONE": "PHONE_IN", "PERSON": "NAME", "LOCATION": "ADDRESS", "IN_AADHAAR": "AADHAAR",
                "IN_PAN": "PAN", "CREDIT_CARD": "CARD_NUMBER", "EMAIL_ADDRESS": "EMAIL"}


@dataclass
class Record:
    id: str
    lang: str
    text: str
    entities: list[dict] = field(default_factory=list)      # {"type", "start", "end"}
    tags: list[str] = field(default_factory=list)          # e.g. "negative", "uncued_name", "native_digits"

    def to_json(self) -> str:
        return json.dumps({"id": self.id, "lang": self.lang, "text": self.text, "entities": self.entities,
                           "tags": self.tags}, ensure_ascii=False, sort_keys=True)


# ---- the built-in synthetic set -------------------------------------------------------------------------------------
_NAMES = {
    "Latn": ["Priya Sharma", "Rahul Verma", "Ananya Iyer", "Arjun Reddy", "Kavitha Nair", "Suresh Patel",
             "Lakshmi Menon", "Venkatesh Rao", "Imran Khan", "Fatima Shaikh", "Harpreet Singh", "Deepa Kulkarni",
             "Karthik Subramanian", "Divya Pillai", "Rohan Banerjee", "Anjali Gupta", "Sanjay Yadav", "Pooja Joshi",
             "Joseph Fernandes", "Meenakshi Sundaram", "Sneha Deshpande", "Farhan Qureshi", "Nandini Chatterjee",
             "Aditya Das"],
    "Deva": ["प्रिया शर्मा", "राहुल वर्मा", "अनन्या गुप्ता", "सुरेश यादव", "पूजा सिंह", "अमित कुमार", "नेहा जोशी",
             "रवि पाटिल", "सुनील कुलकर्णी", "स्नेहा देशपांडे", "मोहम्मद आरिफ", "कविता मिश्रा"],
    "Taml": ["பிரியா ராஜேஷ்", "கார்த்திக் சுப்பிரமணியன்", "லட்சுமி நாராயணன்", "முருகன் செல்வம்", "மீனாட்சி சுந்தரம்",
             "அருண் குமார்", "கவிதா ரமேஷ்"],
    "Telu": ["ప్రియ రెడ్డి", "వెంకటేష్ రావు", "లక్ష్మి దేవి", "రవి కుమార్", "శ్రీనివాస్ రెడ్డి", "అనిత నాయుడు"],
    "Beng": ["প্রিয়া দাস", "সৌরভ বন্দ্যোপাধ্যায়", "অনন্যা সেন", "রাহুল ঘোষ", "মৌমিতা চক্রবর্তী"],
    "Knda": ["ಪ್ರಿಯಾ ಶೆಟ್ಟಿ", "ರವಿ ಕುಮಾರ್", "ಲಕ್ಷ್ಮಿ ಗೌಡ", "ಸುರೇಶ್ ಹೆಗ್ಡೆ", "ಅನಿತಾ ರಾವ್"],
}
_ADDR = {
    "Latn": ["Flat {n}, Shanti Apartments, MG Road, Pune {pin}", "{n}/2, 5th Cross, Indiranagar, Bengaluru {pin}",
             "House No. {n}, Sector 21, Gurugram {pin}", "{n}, Anna Salai, Teynampet, Chennai {pin}"],
    "Deva": ["मकान नंबर {n}, गांधी नगर, जयपुर {pin}", "फ्लैट {n}, शिवाजी नगर, पुणे {pin}"],
    "Taml": ["{n}, அண்ணா நகர், சென்னை {pin}", "{n}, காந்தி தெரு, மதுரை {pin}"],
    "Telu": ["{n}, బంజారా హిల్స్, హైదరాబాద్ {pin}"],
    "Beng": ["{n}, সল্টলেক, কলকাতা {pin}"],
    "Knda": ["{n}, ಜಯನಗರ, ಬೆಂಗಳೂರು {pin}"],
}
_PINS = ["411001", "560038", "122001", "600018", "302001", "625001", "500034", "700091", "560041"]
_DIGIT_BASE = {"Deva": 0x0966, "Beng": 0x09E6, "Taml": 0x0BE6, "Telu": 0x0C66, "Knda": 0x0CE6}

# (template, tags). Slots: {NAME} {PHONE} {EMAIL} {AADHAAR} {PAN} {UPI} {CARD} {VEH} {BANK} {ADDR}
_TEMPLATES: dict[str, tuple[str, list[tuple[str, list[str]]]]] = {
    "en": ("Latn", [
        ("Hi, my name is {NAME} and my number is {PHONE}.", []),
        ("Please update the email for {NAME} to {EMAIL}.", ["uncued_name"]),
        ("{NAME} called about the renewal; Aadhaar {AADHAAR}.", ["uncued_name"]),
        ("PAN {PAN}, account number {BANK}.", []),
        ("I paid through UPI {UPI} yesterday.", []),
        ("My card {CARD} was charged twice.", []),
        ("Car registration {VEH}, policy holder {NAME}.", ["uncued_name"]),
        ("My address is {ADDR}.", []),
        ("Please deliver the documents to {ADDR} by Friday.", ["uncued_address"]),
        ("Spoke to {NAME} from the branch, she will call back on {PHONE}.", ["uncued_name"]),
    ]),
    "hi-Latn": ("Latn", [
        ("Mera naam {NAME} hai aur mera number {PHONE} hai.", []),
        ("{NAME} ji ka email {EMAIL} hai, please update kar do.", ["uncued_name"]),
        ("Aadhaar number {AADHAAR} hai mera, verify kar lo.", []),
        ("Maine {UPI} pe payment kiya tha kal.", []),
        ("Bhai, PAN {PAN} hai, account {BANK} mein refund chahiye.", []),
        ("Gaadi ka number {VEH} hai.", []),
        ("Mera address {ADDR} hai.", []),
        ("Kal {NAME} ne call kiya tha claim ke liye.", ["uncued_name"]),
        ("Card {CARD} se do baar paisa kat gaya.", []),
        ("Mujhe {PHONE} pe call back karo please.", []),
    ]),
    "hi": ("Deva", [
        ("मेरा नाम {NAME} है और मेरा मोबाइल नंबर {PHONE} है।", []),
        ("{NAME} का आधार नंबर {AADHAAR} है।", ["uncued_name"]),
        ("मेरा पता {ADDR} है।", []),
        ("कृपया {EMAIL} पर जानकारी भेजें।", []),
        ("खाता संख्या {BANK} में पैसा वापस करें।", []),
        ("कल {NAME} जी ने शिकायत दर्ज की।", ["uncued_name"]),
        ("मेरा पैन {PAN} है।", []),
    ]),
    "mr": ("Deva", [
        ("माझं नाव {NAME} आहे, माझा नंबर {PHONE} आहे.", []),
        ("{NAME} यांचा ईमेल {EMAIL} आहे.", ["uncued_name"]),
        ("माझा पत्ता {ADDR} आहे.", []),
        ("आधार क्रमांक {AADHAAR}.", []),
    ]),
    "ta-Latn": ("Latn", [
        ("En peyar {NAME}, en number {PHONE}.", ["romanised_cue"]),
        ("{NAME} oda email {EMAIL} update pannunga.", ["uncued_name"]),
        ("Aadhaar {AADHAAR} kudukaren, check pannunga.", []),
        ("UPI {UPI} la anuppunga.", []),
        ("Vandi number {VEH}.", []),
    ]),
    "ta": ("Taml", [
        ("என் பெயர் {NAME}, என் தொலைபேசி எண் {PHONE}.", []),
        ("{NAME} அவர்களின் மின்னஞ்சல் {EMAIL}.", ["uncued_name"]),
        ("முகவரி: {ADDR}", []),
        ("ஆதார் எண் {AADHAAR}.", []),
    ]),
    "te-Latn": ("Latn", [
        ("Naa peru {NAME}, naa number {PHONE}.", ["romanised_cue"]),
        ("{NAME} garu email {EMAIL} ki pampandi.", ["uncued_name"]),
        ("PAN {PAN} ivvandi.", []),
    ]),
    "te": ("Telu", [
        ("నా పేరు {NAME}, నా ఫోన్ నంబర్ {PHONE}.", []),
        ("{NAME} గారి ఆధార్ {AADHAAR}.", ["uncued_name"]),
        ("చిరునామా: {ADDR}", []),
    ]),
    "bn": ("Beng", [
        ("আমার নাম {NAME}, আমার ফোন নম্বর {PHONE}।", []),
        ("{NAME} এর ইমেল {EMAIL}।", ["uncued_name"]),
        ("ঠিকানা: {ADDR}", []),
    ]),
    "kn": ("Knda", [
        ("ನನ್ನ ಹೆಸರು {NAME}, ನನ್ನ ಫೋನ್ ಸಂಖ್ಯೆ {PHONE}.", []),
        ("{NAME} ಅವರ ಇಮೇಲ್ {EMAIL}.", ["uncued_name"]),
        ("ವಿಳಾಸ: {ADDR}", []),
    ]),
}
# Look-alikes: none of these contain personal data (lang, template).
_NEGATIVES = [
    ("en", "Your OTP is {OTP}. Do not share it with anyone."), ("en", "Order {ORDER} has been shipped."),
    ("en", "Premium of Rs {AMT} is due on {DATE}."), ("en", "Ticket number {TICKET} has been closed."),
    ("en", "Claim reference {CLAIMREF} is under review."), ("en", "Policy POL-2026-{SEQ} was renewed."),
    ("en", "Our call centre is open from 9 to 6, Monday to Saturday."), ("en", "Is service available in pincode 560001?"),
    ("hi-Latn", "Aapka OTP {OTP} hai, kisi ko mat batana."), ("hi-Latn", "Order {ORDER} kal tak pahunch jayega."),
    ("hi-Latn", "Kal 3 baje call karna, Rs {AMT} ka payment pending hai."),
    ("hi", "आपका ओटीपी {OTP} है।"), ("hi", "आपका ऑर्डर {ORDER} भेज दिया गया है।"),
    ("ta", "உங்கள் OTP {OTP}."), ("te", "మీ OTP {OTP}."), ("bn", "আপনার OTP {OTP}।"), ("kn", "ನಿಮ್ಮ OTP {OTP}."),
    ("ta-Latn", "Unga order {ORDER} ship aagiduchu."), ("en", "Invoice {INVOICE} for Rs {AMT} attached."),
]


def _native(s: str, script: str) -> str:
    base = _DIGIT_BASE.get(script)
    return "".join(chr(base + int(c)) if base and c.isdigit() else c for c in s)


def _gen(rng: random.Random):
    from .detectors import luhn_valid, verhoeff_check_digit, verhoeff_valid

    def digits(n, first="123456789"):
        return rng.choice(first) + "".join(rng.choice("0123456789") for _ in range(n - 1))

    def phone():
        d = digits(10, "6789")
        return rng.choice([d, f"{d[:5]} {d[5:]}", f"+91 {d}", f"+91-{d[:5]}-{d[5:]}", f"0{d}"])

    def aadhaar():
        d = digits(11, "23456789")
        d += verhoeff_check_digit(d)
        return rng.choice([f"{d[:4]} {d[4:8]} {d[8:]}", d, f"{d[:4]}-{d[4:8]}-{d[8:]}"])

    def card():
        while True:
            d = "4" + digits(15, "0123456789")
            if luhn_valid(d):
                return rng.choice([f"{d[:4]} {d[4:8]} {d[8:12]} {d[12:]}", d])

    def pan():
        up = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        return "".join(rng.choice(up) for _ in range(3)) + "P" + rng.choice(up) + digits(4, "0123456789") + rng.choice(up)

    def veh():
        st = rng.choice(["MH", "KA", "TN", "DL", "TS", "WB", "GJ"])
        return rng.choice([f"{st} {rng.randint(1, 50):02d} {rng.choice(['AB', 'MN', 'CK'])} {digits(4)}",
                           f"{st}{rng.randint(1, 50):02d}{rng.choice(['AB', 'MN', 'CK'])}{digits(4)}",
                           f"{rng.randint(21, 26)} BH {digits(4)} {rng.choice(['AA', 'B'])}"])

    def ticket():
        while True:
            d = digits(12, "23456789")
            if not verhoeff_valid(d):
                return f"{d[:4]} {d[4:8]} {d[8:]}"

    return {"PHONE": phone, "AADHAAR": aadhaar, "CARD": card, "PAN": pan, "VEH": veh, "TICKET": ticket,
            "BANK": lambda: digits(rng.choice([11, 12, 14])), "OTP": lambda: digits(6),
            "ORDER": lambda: digits(10, "12345"), "AMT": lambda: f"{rng.randint(1, 99)},{rng.randint(100, 999)}",
            "DATE": lambda: f"{rng.randint(1, 28):02d}/{rng.randint(1, 12):02d}/2026", "SEQ": lambda: digits(6),
            "CLAIMREF": lambda: digits(10, "6789"), "INVOICE": lambda: "INV-" + digits(8)}


# Which labelled types each hard-case tag is about, for recall per case.
TAG_TYPES = {"uncued_name": ("NAME",), "romanised_cue": ("NAME",), "uncued_address": ("ADDRESS",),
             "native_digits": ("PHONE_IN", "AADHAAR", "ADDRESS")}

SLOT_TYPES = {"NAME": "NAME", "PHONE": "PHONE_IN", "EMAIL": "EMAIL", "AADHAAR": "AADHAAR", "PAN": "PAN",
              "UPI": "UPI_ID", "CARD": "CARD_NUMBER", "VEH": "VEHICLE_REG", "BANK": "BANK_ACCOUNT", "ADDR": "ADDRESS"}


def _fill(template: str, values: dict) -> tuple[str, list[dict]]:
    import re

    out, ents, pos = [], [], 0
    for m in re.finditer(r"\{([A-Z]+)\}", template):
        out.append(template[pos:m.start()])
        start = sum(len(x) for x in out)
        v = values[m.group(1)]
        out.append(v)
        if m.group(1) in SLOT_TYPES:
            ents.append({"type": SLOT_TYPES[m.group(1)], "start": start, "end": start + len(v)})
        pos = m.end()
    out.append(template[pos:])
    return "".join(out), ents


def build_builtin(per_template: int = 4, seed: int = SEED) -> list[Record]:
    """The synthetic ``indic-pii-v1`` set, reproducible from the seed."""
    rng = random.Random(seed)
    g = _gen(rng)
    recs: list[Record] = []
    for lang, (script, templates) in _TEMPLATES.items():
        n = 0
        for template, tags in templates:
            for _ in range(per_template):
                name = rng.choice(_NAMES[script])
                latin_name = rng.choice(_NAMES["Latn"])
                if script == "Latn" and lang != "en" and rng.random() < 0.3:
                    name = name.lower()        # code-mixed chats are often all lower case
                first = name.split()[0].lower() if script == "Latn" else latin_name.split()[0].lower()
                native_digits = script in _DIGIT_BASE and rng.random() < 0.3
                vals = {"NAME": name, "EMAIL": f"{first}.{rng.randint(10, 99)}@mail.example.in",
                        "UPI": f"{first}{rng.randint(1, 99)}@{rng.choice(['okhdfcbank', 'ybl', 'paytm', 'okaxis'])}",
                        "ADDR": rng.choice(_ADDR[script]).format(n=rng.randint(2, 480), pin=rng.choice(_PINS))}
                for k in ("PHONE", "AADHAAR", "PAN", "CARD", "VEH", "BANK"):
                    vals[k] = g[k]()
                if native_digits:
                    for k in ("PHONE", "AADHAAR", "ADDR"):
                        vals[k] = _native(vals[k], script)
                text, ents = _fill(template, vals)
                n += 1
                recs.append(Record(f"{lang}-{n:03d}", lang, text, ents,
                                   sorted(set(tags) | ({"native_digits"} if native_digits and any(
                                       s in template for s in ("{PHONE}", "{AADHAAR}", "{ADDR}")) else set()))))
    for i, (lang, template) in enumerate(_NEGATIVES * 3, 1):
        vals = {k: f() for k, f in g.items()}
        text, _ = _fill(template, vals)
        recs.append(Record(f"neg-{i:03d}", lang, text, [], ["negative"]))
    return recs


def write_builtin(path: Path = BUILTIN) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(r.to_json() + "\n" for r in build_builtin()), encoding="utf-8")
    return path


# ---- loading --------------------------------------------------------------------------------------------------------
def load(path: str | Path | None = None) -> list[Record]:
    p = Path(path) if path else BUILTIN
    out = []
    for i, ln in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
        if not ln.strip():
            continue
        d = json.loads(ln)
        for e in d.get("entities", []):
            if not (0 <= e["start"] < e["end"] <= len(d["text"])):
                raise ValueError(f"{p.name}:{i}: entity {e} is outside the text")
        out.append(Record(str(d.get("id", i)), d.get("lang", "unknown"), d["text"], d.get("entities", []),
                          d.get("tags", [])))
    return out


def from_label_studio(path: str | Path, label_map: dict[str, str] | None = None) -> list[Record]:
    """A Label Studio JSON export (text tasks with span labels) as benchmark records."""
    label_map = label_map or {}
    tasks = json.loads(Path(path).read_text(encoding="utf-8"))
    out = []
    for t in tasks:
        text = (t.get("data") or {}).get("text")
        if not isinstance(text, str):
            continue
        anns = [a for a in t.get("annotations") or [] if not a.get("was_cancelled")]
        ents = []
        for r in (anns[0].get("result") if anns else []) or []:
            v = r.get("value") or {}
            for lab in v.get("labels") or []:
                ents.append({"type": label_map.get(lab, lab), "start": v["start"], "end": v["end"]})
        out.append(Record(str(t.get("id")), (t.get("data") or {}).get("lang", "unknown"), text, ents))
    return out


# ---- scoring --------------------------------------------------------------------------------------------------------
def _norm(t: str) -> str:
    return TYPE_ALIASES.get(t, t)


def _matches(p, g, mode: str) -> bool:
    if _norm(p.type) != g["type"]:
        return False
    if mode == "exact":
        return p.start == g["start"] and p.end == g["end"]
    overlap = min(p.end, g["end"]) - max(p.start, g["start"])
    return overlap > 0 and overlap * 2 >= (g["end"] - g["start"])


def _score(records: list[Record], detect, mode: str) -> dict:
    tp, fn, fp = Counter(), Counter(), Counter()
    by_lang = defaultdict(lambda: [0, 0, 0])
    by_tag = defaultdict(lambda: [0, 0])
    neg_records_flagged = 0
    for r in records:
        preds = list(detect(r.text))
        used = set()
        for g in r.entities:
            hit = next((i for i, p in enumerate(preds) if i not in used and _matches(p, g, mode)), None)
            if hit is None:
                fn[g["type"]] += 1
                by_lang[r.lang][1] += 1
            else:
                used.add(hit)
                tp[g["type"]] += 1
                by_lang[r.lang][0] += 1
            for t in r.tags:
                if g["type"] in TAG_TYPES.get(t, ()):
                    by_tag[t][0 if hit is not None else 1] += 1
        extra = [p for i, p in enumerate(preds) if i not in used]
        for p in extra:
            fp[_norm(p.type)] += 1
            by_lang[r.lang][2] += 1
        if "negative" in r.tags and extra:
            neg_records_flagged += 1

    def prf(t, f_n, f_p):
        p = t / (t + f_p) if t + f_p else None
        rc = t / (t + f_n) if t + f_n else None
        f1 = 2 * p * rc / (p + rc) if p and rc else (0.0 if p is not None and rc is not None else None)
        return {"tp": t, "fn": f_n, "fp": f_p, "precision": _r(p), "recall": _r(rc), "f1": _r(f1)}
    types = sorted(set(tp) | set(fn) | set(fp))
    negs = sum(1 for r in records if "negative" in r.tags)
    return {"overall": prf(sum(tp.values()), sum(fn.values()), sum(fp.values())),
            "by_type": {t: prf(tp[t], fn[t], fp[t]) for t in types},
            "by_lang": {k: prf(*v) for k, v in sorted(by_lang.items())},
            "by_tag": {k: {"found": v[0], "missed": v[1], "recall": _r(v[0] / (v[0] + v[1]) if sum(v) else None)}
                       for k, v in sorted(by_tag.items()) if sum(v)},
            "negatives": {"records": negs, "flagged": neg_records_flagged}}


def _r(x):
    return None if x is None else round(x, 3)


def benchmark(records: list[Record], composite, mode: str = "overlap", per_detector: bool = True) -> dict:
    rep = {"records": len(records), "entities": sum(len(r.entities) for r in records), "match": mode,
           "combined": _score(records, composite.detect, mode)}
    if per_detector and len(getattr(composite, "detectors", [])) > 1:
        rep["by_detector"] = {type(d).__name__: _score(records, d.detect, mode)["overall"]
                              for d in composite.detectors}
    return rep


def check_thresholds(rep: dict, min_recall: dict[str, float], min_precision: dict[str, float]) -> list[str]:
    """Failures for ``TYPE=value`` thresholds (``ALL`` for the overall figure)."""
    out = []
    for kind, limits in (("recall", min_recall), ("precision", min_precision)):
        for t, limit in limits.items():
            row = rep["combined"]["overall"] if t == "ALL" else rep["combined"]["by_type"].get(t)
            got = row and row[kind]
            if got is None or got < limit:
                out.append(f"{t} {kind} {got if got is not None else 'n/a'} < {limit}")
    return out


def markdown(rep: dict, title: str = "PII detection benchmark") -> str:
    c = rep["combined"]

    def v(x):
        return "–" if x is None else f"{x:.2f}"
    lines = [f"# {title}", "", f"{rep['records']} records, {rep['entities']} labelled entities, match: {rep['match']}. "
             f"Overall precision **{v(c['overall']['precision'])}**, recall **{v(c['overall']['recall'])}**, "
             f"F1 **{v(c['overall']['f1'])}**. Look-alike records flagged: {c['negatives']['flagged']} of "
             f"{c['negatives']['records']}.", "", "## By type", "", "| Type | Precision | Recall | F1 | Found | Missed | False positives |",
             "|---|---|---|---|---|---|---|"]
    lines += [f"| {t} | {v(r['precision'])} | {v(r['recall'])} | {v(r['f1'])} | {r['tp']} | {r['fn']} | {r['fp']} |"
              for t, r in c["by_type"].items()]
    lines += ["", "## By language", "", "| Language | Precision | Recall | F1 |", "|---|---|---|---|"]
    lines += [f"| {k} | {v(r['precision'])} | {v(r['recall'])} | {v(r['f1'])} |" for k, r in c["by_lang"].items()]
    if c["by_tag"]:
        lines += ["", "## Hard cases (recall)", "", "| Case | Found | Missed | Recall |", "|---|---|---|---|"]
        lines += [f"| {k} | {r['found']} | {r['missed']} | {v(r['recall'])} |" for k, r in c["by_tag"].items()]
    if rep.get("by_detector"):
        lines += ["", "## Each detector on its own", "", "| Detector | Precision | Recall | F1 |", "|---|---|---|---|"]
        lines += [f"| {k} | {v(r['precision'])} | {v(r['recall'])} | {v(r['f1'])} |" for k, r in rep["by_detector"].items()]
    return "\n".join(lines) + "\n"


if __name__ == "__main__":  # python -m dpdp_rights.pii.benchmark  (regenerate the built-in set)
    print(write_builtin())
