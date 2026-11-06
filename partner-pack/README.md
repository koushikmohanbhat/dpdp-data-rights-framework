# Partner delivery pack

Everything around the code that a partner needs to run a repeatable engagement: from the first workshop
to a verified end-to-end dry run in the client's environment.

The framework is an **accelerator for Data Principal rights in AI agents**. Its core is consent withdrawal and
erasure, with access, correction, nomination and grievance workflows and an evidence trail. It is not a
complete DPDP compliance solution: children's data, Consent Managers and breach response are out of scope
([scope](../docs/dpdp-mapping.md#scope)). Position it that way with clients.

## Your first hour

| # | Do this | Command | You get |
|---|---|---|---|
| 0 | Watch the tour | [demo-tour.mp4](../docs/media/demo-tour.mp4) (two minutes, captioned) | The story before you install anything; send it to a prospect ahead of the first meeting |
| 1 | Install and run the demo | `pip install -e ".[dev]"`, then `python examples/insurance_onboarding/demo.py --html` | `.dpdp/report.html`: the whole story in nine sections |
| 2 | Read the walkthrough next to the report | [demo-walkthrough.md](../docs/demo-walkthrough.md) | What to point at in front of a client, step by step |
| 3 | Run the sector scenarios | `dpdp-rights packs test all --verbose` | The hard cases for insurance, lending and healthcare, in a minute |
| 4 | Start a prospect's folder | `dpdp-rights packs init <sector> --output ~/engagements/<client> --base config/dpdp.production.aws.yaml` | Config, inventory, scenarios, sector questions |
| 5 | Show what is covered | `dpdp-rights -c ~/engagements/<client>/dpdp.yaml coverage --inventory ~/engagements/<client>/inventory.yaml --format html --output coverage.html` | A coverage report to discuss in the first workshop. On a fresh folder every system shows as a gap (no connectors configured yet): that list is the build plan |
| 6 | Show what the client publishes | `dpdp-rights -c ~/engagements/<client>/dpdp.yaml rights notice --format html` | The Rule 14(1) rights notice, from the rules the system enforces |

Then follow the engagement flow below.

## Engagement flow

| Phase | What happens | Assets in this pack and the repo |
|---|---|---|
| **1. Show** | Run the offline demo with the client: tokenisation, lineage, erasure plan, certificate, evidence, other rights; run the sector's scenarios | [Demo walkthrough](../docs/demo-walkthrough.md), `demo.py --html`, `packs test <sector> --verbose` |
| **2. Discover** | Workshop with product, engineering, security and the DPO: purposes, data, systems, processors | [Discovery questionnaire](discovery-questionnaire.md), [inventory template](inventory.template.yaml), [processor register](processor-responsibilities.md) |
| **3. Assess** | Turn the inventory into a coverage report: what is automated, manual, or a gap | `dpdp-rights coverage`, [capability matrix](../docs/capabilities.md) |
| **4. Design** | Start from a [domain pack](../docs/domain-packs.md) (`packs init`); pick the reference architecture, detectors, connectors and policy | [Reference architectures](reference-architectures.md), [PII detection](../docs/pii-detection.md), [configuration](../docs/configuration.md) |
| **5. Build** | Deploy, instrument the agent, connect stores | [Deploy on AWS](../docs/deploy-aws.md) / [GCP](../docs/deploy-gcp.md), [integration guide](../docs/integration-guide.md) |
| **6. Validate** | Live tests, dry run, real erasure in staging, leak test, break-glass drill, reviewer sign-off and evidence bundle | [Testing](../docs/testing.md), [acceptance criteria](implementation-plan.md#acceptance-criteria), [control mapping](control-mapping.md) |
| **7. Operate** | Hand over to the client's operations and DPO teams; monthly audit packs | [Operations runbook](../docs/operations.md), [evidence and audit pack](../docs/evidence.md), [audit evidence checklist](audit-evidence-checklist.md) |

The full plan, with client inputs, deliverables and acceptance criteria per phase:
[implementation-plan.md](implementation-plan.md).

## Templates

| Template | Use it to | Filled in by |
|---|---|---|
| [Discovery questionnaire](discovery-questionnaire.md) | Run the discovery workshop | Partner with product, engineering, security, DPO |
| [Inventory](inventory.template.yaml) | List every system holding personal data; feeds the coverage report | Partner, client engineering |
| [Processor responsibilities](processor-responsibilities.md) | Record how erasure reaches each processor, contract clause and evidence | Client procurement and legal, with the partner |
| [Control mapping](control-mapping.md) | Map DPDP obligations to controls, evidence, owners and tests | DPO and counsel, with the partner |
| [Audit evidence checklist](audit-evidence-checklist.md) | Prepare for an audit or Board inquiry | DPO office |
| [Domain packs](../docs/domain-packs.md) | Start an insurance, lending or healthcare engagement: purposes, holds, patterns, inventory, questions, scenario tests | Partner, with counsel confirming the holds |
| [Implementation plan](implementation-plan.md) | Phases, gates, acceptance criteria, RACI, risks | Partner |

## Measures of success

Track two numbers per engagement, and report them to the client:

1. **Time from kickoff to a verified end-to-end dry run** in the client's environment: a dry-run erasure for
   a test person that lists every system in the inventory.
2. **Share of inventoried systems with tested actions**: the `tested` percentage in the coverage report.

Neither number means the client is compliant. They measure how much of the client's real estate a rights
request reliably reaches, which is what the framework is for.

## Quick start for a new engagement

```bash
mkdir -p ~/engagements/<client>
# insurance | lending | healthcare: merged config, prefilled inventory, scenarios, sector questions
dpdp-rights packs init insurance --output ~/engagements/<client> --base config/dpdp.production.aws.yaml
# no pack for the sector? start from the templates instead:
#   cp partner-pack/inventory.template.yaml ~/engagements/<client>/inventory.yaml
#   cp config/dpdp.production.aws.yaml      ~/engagements/<client>/dpdp.yaml

dpdp-rights -c ~/engagements/<client>/dpdp.yaml coverage \
  --inventory ~/engagements/<client>/inventory.yaml --format html --output ~/engagements/<client>/coverage.html

dpdp-rights packs test insurance --config ~/engagements/<client>/dpdp.yaml \
  --scenarios ~/engagements/<client>/scenarios.yaml          # the domain's hard cases, against the client config
```

Keep client files outside this repository. Re-run the coverage report after each phase; attach it to
status reports and to the final handover.
