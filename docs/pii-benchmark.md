# PII detection benchmark and the NER sidecar

Tokenisation only protects what the detectors find. This page covers two things:

- **The benchmark:** how to measure what the configured detectors find, per type, language and detector.
- **The NER sidecar:** how to add an Indian-language name detector, without building a pipeline, when the numbers say you need one.

## The benchmark

```bash
dpdp-rights -c config.yaml pii-benchmark                                  # built-in set, the config's detectors
dpdp-rights -c config.yaml pii-benchmark --detectors regex,remote_ner     # compare detector sets
dpdp-rights -c config.yaml pii-benchmark --dataset labelled.jsonl --min-recall NAME=0.8 --min-recall ALL=0.9
dpdp-rights -c config.yaml pii-benchmark --label-studio export.json --label-map PERSON=NAME --label-map PHONE=PHONE_IN
```

**What it reports:**
- Precision, recall and F1 per type and per language.
- Recall on the hard cases: names with no cue phrase, romanised cue phrases, addresses with no cue word, native-script digits.
- How many look-alike records were flagged.
- Each detector on its own.

**Thresholds:** `--min-recall` and `--min-precision` (`TYPE=value`, or `ALL`) make it exit 1 when a figure is below the threshold, so a client's pipeline can fail on a regression. `--format json` is for tools.

**Matching:** a labelled entity counts as found when a prediction of the same type overlaps at least half of it (`--match exact` needs the same span). Types other services use are mapped first: `PERSON` → `NAME`, `PHONE` → `PHONE_IN`, `LOCATION` → `ADDRESS` and so on. A prediction that matches nothing is a false positive, whatever its type.

### The built-in set, `indic-pii-v1`

265 synthetic records with 308 labelled entities. They are generated from templates with a fixed seed (`python -m dpdp_rights.pii.benchmark` regenerates them, and a test checks the shipped file matches), so every offset is exact.

| Slice | What it holds |
|---|---|
| `en` | English chat, with and without "my name is"; addresses with and without a cue word |
| `hi-Latn`, `ta-Latn`, `te-Latn` | Romanised code-mixed Hinglish, Tamil-English and Telugu-English, about 30% all lower case |
| `hi`, `mr`, `ta`, `te`, `bn`, `kn` | Native scripts, about 30% with native digits (९८७६५…) |
| `neg-*` | 57 look-alikes: OTPs, order, ticket and invoice numbers, amounts, dates, and claim references shaped like mobile numbers |

The identifiers are synthetic but realistic: Aadhaar numbers pass Verhoeff, cards pass Luhn, mobiles start 6-9, and PAN, UPI, vehicle registration and bank accounts are in their usual shapes. The names are common Indian names in each script.

The set shows how detectors behave on these patterns. **It is not a measure of accuracy on a client's traffic.** For that, label 300-1,000 real messages from the client (in Label Studio or as JSON Lines) and run the benchmark on them; that is the number to put in a readout.

**Format** (one JSON object per line):

```json
{"id": "c-0042", "lang": "hi-Latn", "text": "Mera naam Asha hai", "entities": [{"type": "NAME", "start": 10, "end": 14}], "tags": []}
```

### Baseline: regex only (19 Nov 2026)

`pii-benchmark --detectors regex` on `indic-pii-v1`: precision **0.99**, recall **0.77**, F1 **0.86**. Look-alike records flagged: 3 of 57.

| Type | Precision | Recall | Note |
|---|---|---|---|
| AADHAAR, PAN, EMAIL, UPI_ID, CARD_NUMBER, VEHICLE_REG, BANK_ACCOUNT | 1.00 | 1.00 | Checksums and fixed shapes; native digits included |
| PHONE_IN | 0.94 | 1.00 | The 3 false positives are claim references shaped like mobile numbers |
| ADDRESS | 1.00 | 0.89 | Found after a cue word and up to a PIN code; **0% without a cue** |
| NAME | 1.00 | **0.32** | Found after cue phrases in English, Hinglish and the native scripts; **0% without a cue**; 0% after romanised Tamil and Telugu cues ("en peyar", "naa peru") |

So regex is enough for structured identifiers and not enough for names. Agents in India mostly see names without cue phrases ("Kal Rahul ne call kiya"), so add an NER, cloud or LLM detector.

**Claim numbers that look like phone numbers are flagged on purpose.** Suppressing ten-digit numbers after words like "claim" or "order" would also hide real phone numbers ("claim update 98765… pe bhejo"), and for erasure a missed identifier costs more than a false alarm.

**A bug the benchmark found (fixed the same day).** A 12-digit bank account number written right after "account" that happened to pass the Aadhaar checksum (about 1 in 10 do) was labelled Aadhaar. A context word now beats a coincidental Aadhaar checksum, unless the Aadhaar word itself is nearby.

### IndicNER through the sidecar

The `ner-benchmark` workflow builds the sidecar with AI4Bharat IndicNER and runs the same benchmark for `regex` against `regex,remote_ner`. It runs on main when the detectors or image change, weekly, and on demand, and writes the results to the job summary. It runs in CI rather than here because the model is downloaded from Hugging Face at build time. **IndicNER is a gated model:** accept its terms on Hugging Face with your account, create a read token, and store it as the secret `HF_TOKEN` in the repository's GitHub environment `huggingface`. Without it, the workflow skips with a warning. Expect names in native scripts to improve most, since IndicNER was trained mainly on native-script text. Romanised code-mixed names have to be measured, not assumed; where they stay weak, add the `llm` detector with an in-region model.

## The NER sidecar

`deploy/ner/Dockerfile` builds an image with a token-classification model (default `ai4bharat/IndicNER`) baked in.

- **Offline:** it runs with no internet access.
- **Localhost only:** it listens on `127.0.0.1:8081` and has no authentication, so it must sit inside the same task or pod as its callers.
- **CPU only:** torch runs on CPU, which suits a BERT-base model.

**IndicNER is gated on Hugging Face.** Accept its terms with a Hugging Face account, create a read token, and pass it as a BuildKit secret, which is never stored in an image layer. Other models with open access need no token (`--build-arg MODEL=<id>`).

```bash
export HF_TOKEN=...      # from your secrets manager; never put it in a Dockerfile or a build arg
DOCKER_BUILDKIT=1 docker build --secret id=hf_token,env=HF_TOKEN -f deploy/ner/Dockerfile -t dpdp-ner:indicner .
docker run --rm -e NER_HOST=0.0.0.0 -p 127.0.0.1:8081:8081 dpdp-ner:indicner     # local try-out only
```

```yaml
pii:
  detectors: [regex, remote_ner]
  remote_ner:
    url: http://127.0.0.1:8081
    timeout_seconds: 5
    on_error: raise       # default: if the sidecar is down, protect() fails rather than pass text on unchecked
```

`on_error: skip` carries on with the other detectors instead. Choose it only where availability matters more, and watch the logs.

**Where to run it:** next to everything that calls `protect()`.

- **Rights API and worker on AWS:** set `ner_sidecar_image` in `deploy/terraform/aws`. The container is added to both tasks, which start only once it is healthy. Raise `task_memory` to at least 3072.
- **Your agent:** add the same container to the agent's own ECS task, Kubernetes pod or Cloud Run service (multi-container), with `NER_HOST=127.0.0.1`. For example, in a pod:

  ```yaml
  - name: ner
    image: <registry>/dpdp-ner:indicner
    env: [{name: NER_HOST, value: "127.0.0.1"}]
    resources: {requests: {cpu: "500m", memory: 1536Mi}}
    readinessProbe: {httpGet: {path: /healthz, port: 8081}}
  ```

**API:**
- `POST /v1/ner` with `{"texts": [...]}` (at most 64 texts of 20,000 characters) returns `{"model", "entities": [[{"type", "start", "end", "score"}]]}`.
- `GET /healthz` is the health check.

The model, the `include_locations` option and `min_score` are set with `dpdp-rights ner-serve` options.

**Licence and terms:** check the model's licence and the terms you accepted for the gated download before shipping it in a client image; IndicNER's model card states them. The image holds the model, so treat it as a licensed artefact in your registry.
