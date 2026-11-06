# Two-week DPDP AI readiness assessment

A fixed-scope entry engagement: in ten working days, measure what personal data one or two AI agents handle, where it goes, and what it would take to meet the DPDP obligations for it. It ends with a readout and a scoped implementation proposal (the [implementation plan](implementation-plan.md)).

**Why now:**
- Rule 4 (Consent Managers) and s.6(9) have applied since **13 Nov 2026**.
- Rule 7, the rights mechanics, Rule 8 retention, and the children's rules (Rules 10-12) apply from **13 May 2027**.

**What it is not.** It is not a legal opinion and not a compliance certificate. The readout must never say "compliant". It reports measured gaps, and counsel confirms the legal reading.

## Scope, team and effort

| | |
|---|---|
| Scope | 1-2 AI agents (chat, voice, or agentic workflow) in one cloud, plus the stores they write to |
| Partner team | Lead architect (about 8 days), engineer (about 6 days), privacy or legal liaison (about 2 days) |
| Client team | Product owner for the agent, an engineer with access to its config and logs, the DPO or privacy lead, a security contact |
| Client provides | Architecture notes; read access to config; **a sample of 200-1,000 real conversations**, exported under the client's own controls (sanitised exports undercount); a non-production environment for the gateway |
| Price | Fixed fee, set by the partner from the effort above; the implementation that follows is quoted from the readout |

## The ten days

| Day | Activity | Tools | Output |
|---|---|---|---|
| 1 | Kickoff and the **demo**: one person's data tokenised, tracked, erased, verified and certified, then a breach assessed (10 minutes) | `examples/insurance_onboarding/demo.py --html`, `dpdp-rights packs test <sector> --verbose` | Agreed scope, contacts, data access |
| 1-2 | **Discovery workshop** with the [questionnaire](discovery-questionnaire.md) and the sector pack's questions | `dpdp-rights packs init <sector> --output engagement/` | Answers; draft inventory |
| 2 | Start the **gateway in observe mode** in front of the agent in a test or pilot environment: a base URL change, or the LiteLLM guardrail | [gateway](../docs/gateway.md) | Gateway running; observation window starts |
| 2-4 | **Discovery scan and inventory**: run the read-only scan over the stores you can reach and over exports of the rest, then complete the inventory for every store the agent writes (logs, traces, memory, vector stores, caches, CRMs, eval sets, analytics, processors) | `dpdp-rights -c client.yaml scan --path exports/ --inventory-out draft.yaml` ([scan](../docs/scan.md)), [inventory template](inventory.template.yaml), [processor register](processor-responsibilities.md) | Where raw personal data sits today; `inventory.yaml`; processor register |
| 3-4 | **PII sample scan** of the client's conversations with the detectors they could run (regex, plus the cloud detector, plus IndicNER where available) | `dpdp-rights pii-scan --input sample.jsonl --format md` | What kinds of personal data appear, and what each detector adds |
| 4-5 | **Detector benchmark**: label 300+ of the sampled messages (Label Studio or JSON Lines) and measure precision and recall per type and language for the candidate detector sets | `dpdp-rights pii-benchmark --label-studio export.json --detectors regex,remote_ner` | Measured recall for names and identifiers on the client's own traffic; the detector choice |
| 5 | **Coverage report**: the inventory against connectors, tested actions, retention and processor contracts | `dpdp-rights coverage --inventory inventory.yaml --format html` | Coverage gaps (`--fail-on-gaps` lists them) |
| 5-6 | **Draft configuration**: purposes, legal bases, legal holds from the sector pack; run the pack's scenarios against it | `dpdp-rights packs test <sector> --config client.yaml` | Draft config; scenario results |
| 6-7 | **Rights and consent review**: how access, correction, erasure, withdrawal, nomination and grievances arrive today; Consent Manager plans; children or wards among users | [rights](../docs/rights.md), [Consent Managers](../docs/consent-managers.md), [children](../docs/children.md) | Rights-channel gap list |
| 7 | **Breach readiness**: can the client say who was affected by a compromise of the store they consider riskiest, and draft the Rule 7 intimations within 72 hours? | `dpdp-rights breach assess` in the demo; tabletop questions | Breach readiness notes |
| 8 | Close the gateway observation window and collect its report | `dpdp-rights gateway report --since <day 2> --format md` | Measured flows: personal data per purpose and model; identification rate; would-be refusals |
| 8-9 | **Control gap view**: [control mapping](control-mapping.md) C01-C24 marked met, partly met or not met, with evidence | | Gap view |
| 9 | Size the implementation: phases from the [implementation plan](implementation-plan.md), connectors to build, detectors to add, acceptance criteria | | Scoped proposal |
| 10 | **Readout** to the sponsor, DPO and engineering lead | [readout template](assessment-readout.template.md) | Readout and proposal; list of questions for counsel |

## Evidence the readout rests on

All of it is produced from the client's own systems and data, never from the demo:

1. **The scan report:** which stores and exports already hold raw personal data, of which kinds, and how much is tokenised.
2. **The gateway report:** measured, not estimated. It shows what share of model calls carry personal data, which kinds, for which purposes, whether the person can be identified, and how many calls enforce mode would refuse today for lack of a consent record.
3. **The PII sample scan and benchmark:** the scan shows which kinds of personal data appear in real conversations and which detectors find them; the benchmark on a labelled subset measures what each detector set misses. If IndicNER or the LLM detector lifts name recall, that is the case for adding them.
4. **The coverage report:** which inventoried systems can be searched, erased and verified, which need manual procedures, and which processors lack contract references.
5. **Pack scenario results** against the draft config: whether the sector holds and policies behave as intended.
6. **The control gap view**, with one line of evidence per control.

## Handling the client's data

- **Where it runs:** run `pii-scan` and the gateway inside the client's environment. Reports hold counts only, but the sample and the gateway's traffic are real personal data.
- **Retention:** delete the sample at the end of the engagement and record that in the readout.
- **Gateway mode:** in observe mode the gateway changes nothing on the wire. Agree with security where it runs, and switch it off at the end unless the client keeps it.

## Exit criteria

- The readout has been delivered.
- Every C01-C24 control has a status and evidence.
- The counsel question list has been handed over.
- The sample has been deleted.
- The gateway is removed, or handed over in observe mode.
- An implementation proposal has been issued, with phases and the acceptance criteria that apply (A1-A18).
