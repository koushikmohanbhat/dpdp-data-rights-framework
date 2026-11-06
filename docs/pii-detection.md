# PII detection

Tokenisation only protects what the detectors find. This guide covers the detectors, how to combine them
for Indian data, format-preserving tokens, and documents.

Detectors run inside `protect()` before anything reaches a model, log, index or store. Configure them in
`pii.detectors`. All configured detectors run, and their results are merged; where findings overlap, the
longer span wins, then the higher score.

## The detectors

| Detector | Finds | Indian languages | Where the text goes | Cost |
|---|---|---|---|---|
| `regex` (always include) | Structured identifiers (below), names after cue words, addresses after a cue word ending in a PIN code | Digits in all Indian scripts; name cues in Hinglish and 9 languages | Nowhere: in-process | Free |
| `presidio` | Names (spaCy or transformers NER), email, phone, card, IBAN, IP, plus Presidio's India recognisers (Aadhaar, PAN, passport, voter ID, vehicle, GSTIN) | English NER only | Nowhere: in-process | Free; CPU |
| `transformers_ner` | Person names (and locations, if enabled) with any Hugging Face model; default `ai4bharat/IndicNER` covers 11 Indian languages | Yes | Nowhere: model runs in your process | Free; GPU recommended |
| `aws_comprehend` | Names, addresses, phone, email, Aadhaar, PAN, voter ID, bank account, card | English only | Amazon Comprehend in your account | Per character |
| `bedrock_guardrail` | The PII types and regexes in a Bedrock guardrail you define | As configured | Bedrock in your account | Per text unit |
| `gcp_dlp` | Names, addresses, phone, email, card, Aadhaar, PAN, passport, GST | Partly | Cloud DLP in your project | Per byte |
| `llm` (opt-in) | Anything a model can recognise: names without cues, addresses, transliterated and mixed-language text, health statements | Yes | **Raw text goes to the configured model** | Per token |

### Structured identifiers in `regex`

Email, UPI ID, Aadhaar (Verhoeff checksum), card number (Luhn), PAN, Indian mobile numbers, vehicle
registration (state codes and BH series), GSTIN (checksum), ABHA number, driving licence. Voter ID (EPIC),
passport and bank account numbers are reported only after a context word ("voter id", "passport",
"account number", "खाता"), because their formats collide with invoice and order numbers.

Digits written in Devanagari, Bengali, Gurmukhi, Gujarati, Odia, Tamil, Telugu, Kannada or Malayalam
are recognised: `२३४५ ६७८९ ०१२४` is detected as an Aadhaar number.

## Recommended combinations

| Deployment | `pii.detectors` | Notes |
|---|---|---|
| Development, demos | `[regex]` | Production refuses regex alone unless `allow_regex_only` is set after review |
| AWS, English | `[regex, aws_comprehend]` | Add `bedrock_guardrail` to reuse a guardrail already fronting your agents |
| AWS or GCP, Indian languages | `[regex, aws_comprehend, transformers_ner]` or `[regex, gcp_dlp, transformers_ner]` | IndicNER covers names in Indian scripts that the cloud services miss |
| Data must not leave your environment | `[regex, presidio, transformers_ner]` | All in-process; use `en_core_web_lg` or a transformers model with Presidio |
| Hardest cases (free text, transliteration, addresses) | add `llm` | With a separate, in-region model (below) |

Measure on your own data before go-live: take a sample of real conversations (in a secure environment),
label the personal data, and check what each combination finds and misses.

## The `llm` detector

The best coverage for Hinglish, transliterated names, addresses without cue words and health statements,
at a price: **the raw text is sent to the detection model before tokenisation**. Use it only with a model
you control:

```yaml
pii:
  detectors: [regex, aws_comprehend, llm]
  llm:                       # separate from `provider` (the agent's model)
    type: bedrock
    model: <a model or inference profile available in your region>
    region: ap-south-1
```

- Use a model in your own cloud account and region, with model invocation logging off for this model.
- Avoid direct third-party APIs that retain prompts, unless you have a zero-data-retention agreement.
- Keep it separate from the agent's model, so the agent's model only ever sees tokenised text.

`check-config` warns about each of these. The detector only accepts values that appear exactly in the
input, so a model that invents a value cannot cause anything to be tokenised. If the model call fails,
the other detectors still run.

## Installing the optional detectors

```bash
pip install "dpdp-data-rights-framework[presidio]"
python -m spacy download en_core_web_lg

pip install "dpdp-data-rights-framework[indic-ner]"          # transformers + torch
# the IndicNER model downloads on first use; in production bake it into the image and set
# pii.transformers_ner.model to its local path
```

## Format-preserving tokens

Standard tokens look like `<PHONE_IN_3f9a1c0b7d2e>`. Two opt-in alternatives, for when that shape breaks
something:

### Masked display

For showing data to the person it belongs to without revealing it fully:

```python
answer.reveal(masked=True)                       # "+91 ••••• •3210", "p••••@example.in", "P•••• S•••••"
dpdp.vault.reveal(text, {principal_id}, masked=True)
```

Storage is unchanged; this is display only.

### Storage surrogates

For systems that validate formats (a CRM phone field, a payments field, a legacy screen), store a
same-shaped fake value instead of a token:

```yaml
pii:
  surrogates: [PHONE_IN, AADHAAR, EMAIL]
```

`+91 98765 43210` is stored as something like `+91 74012 58836`. Surrogates:

- are derived from the person's key, like tokens, so the same value always gets the same surrogate (joins
  and caching still work), and crypto-shredding makes them meaningless;
- keep separators, length, character classes, the `+91` prefix, the PAN holder-type letter, and a valid
  first digit;
- **can never be a real Aadhaar or card number**: they deliberately fail the Verhoeff or Luhn check;
  emails use the reserved `surrogate.invalid` domain;
- are recognised by the vault when text passes through again, so they are not tokenised twice, and are
  found by reveal, lineage, discovery, redaction and verification like any token.

Trade-offs: surrogate phone numbers and PANs are indistinguishable from real ones to a human reading a log,
and a real number that happens to equal an existing surrogate (very unlikely) would not be tokenised. Use
surrogates only for the fields that need them.

Supported types: `PHONE_IN`, `PHONE`, `AADHAAR`, `CARD_NUMBER`, `PAN`, `EMAIL`, `BANK_ACCOUNT`.

## Documents: PDFs, scans, ID card photos

```python
with dpdp.context(pid, purpose="kyc"):
    doc = dpdp.protect_document(pdf_bytes, filename="aadhaar.pdf")
doc.text        # tokenised text, safe to store, embed or send to a model
doc.entities    # each detection with its page number
```

| Input | How text is extracted | Configuration |
|---|---|---|
| PDF with a text layer | Locally with `pypdf`; nothing leaves your environment | `pip install "...[documents]"` |
| Scanned PDF, PNG, JPEG, TIFF | Amazon Textract | `pii.documents: {ocr: textract, region: ap-south-1}` |
| Multi-page scanned PDF on S3 | Textract asynchronous job | `protect_document(s3_uri="s3://bucket/key.pdf")` |
| Scans and images on Google Cloud | Document AI OCR processor | `pii.documents: {ocr: document_ai, processor: projects/.../processors/...}` |

The extracted text goes through the same detectors and tokenisation as `protect()`. The original file
still contains the personal data: keep it in a store with a connector (for example `aws_s3_objects`) and
register it with `track_artifact`, so erasure deletes it. Redacting the image itself (black boxes over
the identifiers) is on the [roadmap](roadmap.md).

## Limits

- Detection is probabilistic. Data the detectors miss is stored as written, and is only found later if a
  connector can search for it. Verification reports what it finds; it cannot prove absence.
- Names without cue words in Indian scripts need `transformers_ner` or `llm`. Addresses without a cue
  word or PIN code need a cloud detector, Presidio with locations enabled, or `llm`.
- The regex name cues tokenise the words after the cue; occasionally they include a word that is not
  part of the name.
