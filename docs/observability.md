# Observability (OpenTelemetry)

Observability pipelines are one of the easiest places for personal data to leak: auto-instrumented
LLM SDKs often record full prompts and completions as span attributes. The framework handles this
in three layers.

## 1. Tag every span with the pseudonymous principal

`PrincipalSpanProcessor` runs on span start. Any span created inside `dpdp.context(...)`,
including spans from OpenAI, Anthropic, Bedrock, LangChain or HTTP auto-instrumentation, gets:

| Attribute | Value |
|---|---|
| `dpdp.principal` | pseudonymous id (`dp_...`), never an identifier |
| `dpdp.purpose` | purpose of processing |
| `session.id` | agent session id, if set |

This makes traces discoverable per person (for erasure and verification) without storing who they are.

## 2. Tokenise before export

`TokenizingSpanExporter` wraps whatever exporter you use. Before export it rewrites span attributes
and span event attributes:

- spans with `dpdp.principal`: personal data is replaced with that principal's vault tokens, so it
  becomes unreadable when the principal is erased
- spans without it (batch jobs, health checks): personal data is masked as `[EMAIL]`, `[PHONE_IN]`,
  `[AADHAAR]`...

## 3. Framework telemetry

Spans (attributes are ids and counts, never content):

| Span | Key attributes |
|---|---|
| `dpdp.erasure` | `dpdp.request_id`, `dpdp.scope`, `dpdp.principal`, `dpdp.status` |
| `gen_ai.generate` | `gen_ai.system`, `gen_ai.request.model`, `gen_ai.usage.*` (GenAI semantic conventions) |

Metrics:

| Metric | Type | Labels |
|---|---|---|
| `dpdp.erasure.requests` | counter | status, scope |
| `dpdp.erasure.actions` | counter | action, store, ok |
| `dpdp.erasure.duration` | histogram (s) | scope |
| `dpdp.erasure.open` | gauge | sla = ok / due_soon / overdue |
| `dpdp.consent.withdrawals` | counter | purpose |
| `dpdp.processing.blocked` | counter | purpose |
| `dpdp.pii.tokenized` | counter | type |

Alert on `dpdp.erasure.open{sla="overdue"} > 0` and on failed `dpdp.erasure.actions`.

## Setup

```bash
pip install -e ".[otel]"
```

```yaml
observability:
  otel: true
  service_name: dpdp-rights
  otlp_endpoint: http://localhost:4318      # ADOT / OpenTelemetry Collector
  tokenize_spans: true
```

`dpdp-rights serve` and `dpdp-rights worker` install the provider automatically when `otel: true`.
In your own agent process:

```python
from dpdp_rights.observability.telemetry import install
install(dpdp)                       # OTLP/HTTP to observability.otlp_endpoint
# or: install(dpdp, exporter=MyExporter(), metric_reader=PeriodicExportingMetricReader(...))
```

Install this provider **before** enabling LLM auto-instrumentation so those spans flow through it.

## Collector and backends

| Cloud | Collector config | Traces | Metrics |
|---|---|---|---|
| AWS | `deploy/otel/collector-aws.yaml` (ADOT) | X-Ray (`dpdp.principal` indexed as annotation) | CloudWatch (EMF) |
| GCP | `deploy/otel/collector-gcp.yaml` | Cloud Trace | Managed Prometheus / Cloud Monitoring |

Both configs add the collector's `redaction` processor as defence in depth for spans from services
that don't use the framework.

AgentCore Observability already sends agent spans to CloudWatch (`aws/spans`); the
`aws_cloudwatch_logs` connector covers them. Vertex AI Agent Engine traces go to Cloud Trace; the
`gcp_cloud_trace` connector covers them.

## Erasure coverage of observability stores

| Store | Connector | Can delete? | What the framework does |
|---|---|---|---|
| CloudWatch Logs (incl. `aws/spans`) | `aws_cloudwatch_logs` | No (per event) | Discover via Logs Insights, crypto-shred, verify no raw values, check retention |
| AWS X-Ray | `aws_xray` | No | Discover via `dpdp_principal` annotation, crypto-shred, verify segments, expires with X-Ray retention |
| Cloud Logging | `gcp_cloud_logging` | No (per entry) | Discover, crypto-shred, verify |
| Cloud Trace | `gcp_cloud_trace` | No | Discover via `dpdp.principal` label, crypto-shred, verify spans |
| Langfuse | `langfuse` | Yes | Find traces by `userId` (= pseudonymous id), delete |

For stores without per-record deletion, prevention (tokenisation) is the control and verification
is the proof.
