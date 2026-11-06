# Getting started

Three paths, in the order most teams take them.

| Path | Time | You get |
|---|---|---|
| [1. Try it locally](#1-try-it-locally) | 5 minutes | The demo running on your laptop, no cloud account |
| [2. Integrate it into an agent](#2-integrate-it-into-an-agent) | 1–3 days | Your agent tokenising data, recording consent and lineage |
| [3. Deploy to production](#3-deploy-to-production) | 1–2 weeks incl. reviews | API, workers, vault and certificates running in your cloud account |

## 1. Try it locally

Requirements: Python 3.10+, git. No cloud account or API key.

```bash
git clone https://github.com/koushikmohanbhat/dpdp-data-rights-framework.git
cd dpdp-data-rights-framework
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

Prefer not to run anything yet? Watch the [two-minute captioned tour](media/demo-tour.mp4) of the demo report.

Then see the framework in three ways:

| Way | Command | Best for |
|---|---|---|
| **Visual report** | `python examples/insurance_onboarding/demo.py --html`, then open `.dpdp/report.html` in a browser | A first look, and showing customers, DPOs or partner teams |
| **Guided walkthrough** | Read [demo-walkthrough.md](demo-walkthrough.md) next to the report | Understanding each step and the DPDP obligation behind it; a presenter script |
| **Rights API, hands-on** | `dpdp-rights -c config/dpdp.local.yaml serve --port 8080`, then open http://localhost:8080/docs (works offline; use the `x-dev-user` field to act as different people) | Submitting withdrawals, erasures, access requests and grievances yourself, signing cases off and exporting evidence ([steps](demo-walkthrough.md#try-it-yourself-through-the-api)) |

What one demo run leaves in `.dpdp/`:

| File | What it is |
|---|---|
| `report.html` | The visual report: nine sections, from tokenisation to the other rights |
| `evidence/case.html` | Priya's case record: actions, exceptions, certificate check, manual step, sign-off |
| `evidence/er_*.zip`, `evidence/audit-pack.zip` | A signed evidence bundle and an audit pack; check them with `dpdp-rights evidence verify <zip>` |
| `rights/access-report-rahul.html` | What a Data Principal receives for an access request (values masked) |
| `rights/notice.md` | The Rule 14(1) notice to publish on a website, generated from the rules |

Useful extras:

```bash
python examples/insurance_onboarding/demo.py --html --leak   # verification catches a raw phone number in a log
dpdp-rights -c config/dpdp.local.yaml worker --once          # process queued API requests
dpdp-rights packs test all --verbose                          # insurance, lending, healthcare scenarios, offline
pytest -q                                                     # unit tests (live cloud tests are skipped)
```

The demo writes its state to `.dpdp/` in the current folder and starts fresh on every run.

To use a real model in the demo, install the extra and set the provider, for example:

```bash
pip install -e ".[openai]"   && DPDP_PROVIDER=openai DPDP_MODEL=<model> python examples/insurance_onboarding/demo.py --html
pip install -e ".[aws]"      # then set DPDP_PROVIDER=bedrock, DPDP_MODEL=<model or inference profile ID>
```

## Running a client engagement

Partners: start with the [partner delivery pack](../partner-pack/README.md). Its "First hour" section takes
you from the demo to a prospect's engagement folder. In short:

```bash
dpdp-rights packs init insurance --output ~/engagements/<client> --base config/dpdp.production.aws.yaml   # or lending / healthcare
dpdp-rights -c ~/engagements/<client>/dpdp.yaml coverage --inventory ~/engagements/<client>/inventory.yaml
dpdp-rights packs test insurance --config ~/engagements/<client>/dpdp.yaml
```

## 2. Integrate it into an agent

Follow the [integration guide](integration-guide.md). In short:

1. **Model the purposes** your agent processes data for, and which need consent versus legitimate use.
2. **Pick your stores** and add a connector for each (agent memory, vector store, logs, eval sets...).
3. **Wrap processing** in `dpdp.context(...)`, pass user input through `protect()`, and call
   `track_artifact()` wherever the agent persists something.
4. **Attach the logging filter** and, if you use OpenTelemetry, the tokenising exporter.
5. **Test an erasure** with `dpdp.erase(pid, dry_run=True)` and check the plan covers every store.

## 3. Deploy to production

| Cloud | Guide | Automation |
|---|---|---|
| AWS | [deploy-aws.md](deploy-aws.md) | Terraform: vault, keys, database, ECS API + worker, ADOT, Cognito, schedules |
| Google Cloud | [deploy-gcp.md](deploy-gcp.md) | Terraform for keys, vault, IAM; Cloud Run via `gcloud` |

Before go-live:

- Validate the connectors you use against your own account: [testing.md](testing.md)
- Review [security.md](security.md) and [limitations.md](limitations.md)
- Hand the [operations runbook](operations.md) to whoever runs it day to day
- Have privacy counsel review purposes, legal holds and retention ([dpdp-mapping.md](dpdp-mapping.md)), the rights
  rule set ([rights.md](rights.md#legal-rules)) and any domain pack's holds ([domain-packs.md](domain-packs.md))
- Set up reviewers and the evidence routine ([evidence.md](evidence.md))
