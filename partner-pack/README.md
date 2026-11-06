# Partner delivery pack

Everything around the code that a partner needs to run a repeatable engagement: from the first workshop
to a verified end-to-end dry run in the client's environment.

The framework is an **accelerator for consent withdrawal and erasure** in AI agents, not a complete DPDP
compliance solution ([scope](../docs/dpdp-mapping.md#scope)). Position it that way with clients.

## Engagement flow

| Phase | What happens | Assets in this pack and the repo |
|---|---|---|
| **1. Show** | Run the offline demo with the client: tokenisation, lineage, erasure plan, certificate | [Demo walkthrough](../docs/demo-walkthrough.md), `demo.py --html` |
| **2. Discover** | Workshop with product, engineering, security and the DPO: purposes, data, systems, processors | [Discovery questionnaire](discovery-questionnaire.md), [inventory template](inventory.template.yaml) |
| **3. Assess** | Turn the inventory into a coverage report: what is automated, manual, or a gap | `dpdp-rights coverage`, [capability matrix](../docs/capabilities.md) |
| **4. Design** | Pick the reference architecture, detectors, connectors and policy | [Reference architectures](reference-architectures.md), [PII detection](../docs/pii-detection.md), [configuration](../docs/configuration.md) |
| **5. Build** | Deploy, instrument the agent, connect stores | [Deploy on AWS](../docs/deploy-aws.md) / [GCP](../docs/deploy-gcp.md), [integration guide](../docs/integration-guide.md) |
| **6. Validate** | Live tests, dry run, real erasure in staging, leak test, break-glass drill | [Testing](../docs/testing.md), [acceptance criteria](implementation-plan.md#acceptance-criteria) |
| **7. Operate** | Hand over to the client's operations and DPO teams | [Operations runbook](../docs/operations.md) |

The full plan, with client inputs, deliverables and acceptance criteria per phase:
[implementation-plan.md](implementation-plan.md).

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
cp partner-pack/inventory.template.yaml ~/engagements/<client>/inventory.yaml   # fill in during discovery
cp config/dpdp.production.aws.yaml        ~/engagements/<client>/dpdp.yaml        # or the GCP template

dpdp-rights -c ~/engagements/<client>/dpdp.yaml coverage \
  --inventory ~/engagements/<client>/inventory.yaml --format html --output ~/engagements/<client>/coverage.html
```

Keep client files outside this repository. Re-run the coverage report after each phase; attach it to
status reports and to the final handover.
