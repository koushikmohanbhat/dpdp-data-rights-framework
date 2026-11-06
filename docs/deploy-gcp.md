# Deploy on Google Cloud

This guide deploys the framework into **your own Google Cloud project**. The Terraform stack in
[`deploy/terraform/gcp`](../deploy/terraform/gcp) creates the security-critical resources (keys,
vault, certificate bucket, service account and roles). The database, Cloud Run services and identity
provider are set up with `gcloud`, because most organisations already have standards for those.

Nothing project-specific lives in this repository. Keep your `terraform.tfvars` and config file in a
private folder or repository of your own.

## What gets deployed

| Component | Resource | Created by |
|---|---|---|
| Vault key | Cloud KMS key `dpdp/vault-kek`, 90-day rotation | Terraform |
| Sealed key | Cloud KMS key `dpdp/sealed-kek`: app can encrypt only, decrypt for your break-glass group | Terraform |
| Certificate signing | Cloud KMS asymmetric key `dpdp/cert-signing` (EC P-256) | Terraform |
| Vault storage | Firestore Native database `dpdp-vault` | Terraform |
| Certificate archive | GCS bucket `<project>-dpdp-certificates` with a **locked** retention policy | Terraform |
| Service account | `dpdp-erasure@<project>.iam.gserviceaccount.com` with least-privilege roles | Terraform |
| Escrow purge schedule | Cloud Scheduler job, daily 02:00 IST (when `purge_job_uri` is set) | Terraform |
| Control-plane DB | Cloud SQL for PostgreSQL (or AlloyDB), private IP | You (`gcloud`) |
| Rights API | Cloud Run service `dpdp-rights serve`, internal ingress, collector sidecar | You (`gcloud`) |
| Worker | Cloud Run service `dpdp-rights worker` (or a scheduled job with `worker --once`) | You (`gcloud`) |
| Purge job | Cloud Run job `dpdp-rights purge-escrows` | You (`gcloud`) |
| Identity | Identity Platform with a `roles` custom claim | You |

## Prerequisites

- `gcloud` CLI, Terraform ≥ 1.6, Docker, Python 3.10+ with the framework installed
- A project with billing, and these APIs enabled:
  ```bash
  gcloud services enable cloudkms.googleapis.com firestore.googleapis.com run.googleapis.com \
    sqladmin.googleapis.com artifactregistry.googleapis.com cloudscheduler.googleapis.com \
    secretmanager.googleapis.com aiplatform.googleapis.com dlp.googleapis.com \
    logging.googleapis.com cloudtrace.googleapis.com identitytoolkit.googleapis.com
  ```
- A VPC with a subnet in your region for Cloud Run Direct VPC egress and Cloud SQL private IP
- A Google group for break-glass access, for example `group:dpdp-break-glass@yourcompany.in`
- Vertex AI model access in your region (for India data residency, `asia-south1` Mumbai or
  `asia-south2` Delhi; check model availability there)

The production config template uses `asia-south1` in its KMS and Agent Engine resource names. If you
deploy elsewhere, change those paths in your copy.

## Step 1: Prepare your config

```bash
mkdir -p ~/my-dpdp-deployment
cp config/dpdp.production.gcp.yaml ~/my-dpdp-deployment/dpdp.yaml
```

Edit `purposes`, `connectors` and `policy` for your agent (see the
[integration guide](integration-guide.md) and [configuration.md](configuration.md)). The template's
placeholders:

| Variable | Value |
|---|---|
| `GOOGLE_CLOUD_PROJECT` | Your project ID |
| `DPDP_VAULT_PROJECT` | Project holding the Firestore vault (the same project, or a separate one) |
| `DPDP_VAULT_DATABASE` | Firestore database name (default `dpdp-vault`, created by Terraform) |
| `DPDP_LINEAGE_URL` | PostgreSQL URL for the control plane, from Secret Manager |
| `TENANT`, `DPDP_PROVIDER`, `VERTEX_MODEL`, `VERTEX_LOCATION` | Optional overrides |
| `AGENT_ENGINE_ID`, `INDEX_ID` | IDs used by the example connectors; remove the connectors you don't use |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | Collector endpoint, default `http://localhost:4318` (the sidecar) |

Check it with `dpdp-rights -c ~/my-dpdp-deployment/dpdp.yaml check-config` (set dummy values for the
variables first).

## Step 2: Apply Terraform

```bash
cat > ~/my-dpdp-deployment/gcp.tfvars <<'EOF'
project           = "<your-project-id>"
region            = "asia-south1"
break_glass_group = "group:dpdp-break-glass@yourcompany.in"
# certificate_retention_days = 3650
# purge_job_uri = "https://run.googleapis.com/v2/projects/<project>/locations/<region>/jobs/dpdp-purge-escrows:run"
EOF

cd deploy/terraform/gcp
terraform init
terraform apply -var-file ~/my-dpdp-deployment/gcp.tfvars
```

**The certificate bucket's retention policy is locked.** Locking is irreversible: no one can delete
objects before the retention period ends, and the bucket cannot be deleted while they exist. For a test
project, set `certificate_retention_days = 1`.

Leave `purge_job_uri` empty for now; you set it in Step 6 once the job exists.

## Step 3: Create the database

```bash
REGION=asia-south1
gcloud sql instances create dpdp-control-plane --database-version=POSTGRES_16 --region=$REGION \
  --tier=db-custom-2-7680 --availability-type=REGIONAL --network=<your-vpc> --no-assign-ip \
  --require-ssl --deletion-protection
gcloud sql databases create dpdp --instance=dpdp-control-plane
gcloud sql users create dpdp --instance=dpdp-control-plane --password="$(openssl rand -base64 30)"

# store the full URL as a secret (URL-encode the password)
printf 'postgresql+psycopg://dpdp:<url-encoded-password>@<private-ip>:5432/dpdp?sslmode=require' |
  gcloud secrets create dpdp-lineage-url --data-file=-
gcloud secrets add-iam-policy-binding dpdp-lineage-url \
  --member=serviceAccount:dpdp-erasure@<project>.iam.gserviceaccount.com --role=roles/secretmanager.secretAccessor
```

Store the config itself as a secret too, so it is not baked into the image:

```bash
gcloud secrets create dpdp-config --data-file=$HOME/my-dpdp-deployment/dpdp.yaml
gcloud secrets add-iam-policy-binding dpdp-config \
  --member=serviceAccount:dpdp-erasure@<project>.iam.gserviceaccount.com --role=roles/secretmanager.secretAccessor
```

## Step 4: Build and push the image

```bash
gcloud artifacts repositories create dpdp --repository-format=docker --location=$REGION
IMAGE=$REGION-docker.pkg.dev/<project>/dpdp/dpdp-rights:0.2.0
gcloud auth configure-docker $REGION-docker.pkg.dev
docker build --platform linux/amd64 --build-arg EXTRAS=gcp,openai,anthropic,api,postgres,otel,auth \
  -t $IMAGE . && docker push $IMAGE
```

The `EXTRAS` build argument picks the cloud SDKs installed in the image (the default is the AWS set).

## Step 5: Deploy the API and worker

The config secret is mounted as a file at `/config/dpdp.yaml`, which is the image's default
`DPDP_CONFIG`.

```bash
SA=dpdp-erasure@<project>.iam.gserviceaccount.com
COMMON="--region=$REGION --service-account=$SA --network=<your-vpc> --subnet=<your-subnet> \
  --vpc-egress=private-ranges-only --set-secrets=/config/dpdp.yaml=dpdp-config:latest,DPDP_LINEAGE_URL=dpdp-lineage-url:latest \
  --set-env-vars=GOOGLE_CLOUD_PROJECT=<project>,DPDP_VAULT_PROJECT=<project>"

gcloud run deploy dpdp-rights-api --image=$IMAGE $COMMON --ingress=internal --no-allow-unauthenticated \
  --args=serve,--port,8080 --port=8080 --min-instances=1

gcloud run deploy dpdp-rights-worker --image=$IMAGE $COMMON --ingress=internal --no-allow-unauthenticated \
  --args=worker --no-cpu-throttling --min-instances=1 --max-instances=1
```

Notes:

- `--no-allow-unauthenticated` puts Cloud Run IAM in front of the framework's own authentication:
  callers need `roles/run.invoker` **and** a valid API key or Identity Platform token. If your callers
  cannot present Google identity tokens, put an internal load balancer with IAP or your API gateway in
  front instead.
- The worker polls the job queue, so it needs CPU outside requests (`--no-cpu-throttling`). Instead you
  can run `worker --once` as a Cloud Run job every few minutes from Cloud Scheduler.
- **Collector**: add the OpenTelemetry Collector as a sidecar container (Cloud Run multi-container,
  deployed from a YAML service definition) with [`deploy/otel/collector-gcp.yaml`](../deploy/otel/collector-gcp.yaml).
  It masks PII patterns and exports traces to Cloud Trace and metrics to Managed Service for Prometheus.
  Grant the service account `roles/monitoring.metricWriter` for metrics.

## Step 6: Schedule the escrow purge

```bash
gcloud run jobs create dpdp-purge-escrows --image=$IMAGE --region=$REGION --service-account=$SA \
  --network=<your-vpc> --subnet=<your-subnet> --vpc-egress=private-ranges-only \
  --set-secrets=/config/dpdp.yaml=dpdp-config:latest,DPDP_LINEAGE_URL=dpdp-lineage-url:latest \
  --set-env-vars=GOOGLE_CLOUD_PROJECT=<project>,DPDP_VAULT_PROJECT=<project> --args=purge-escrows

gcloud run jobs add-iam-policy-binding dpdp-purge-escrows --region=$REGION \
  --member=serviceAccount:$SA --role=roles/run.invoker
```

Then set `purge_job_uri` in your tfvars to
`https://run.googleapis.com/v2/projects/<project>/locations/<region>/jobs/dpdp-purge-escrows:run` and
`terraform apply` again.

## Step 7: Identity

Systems use API keys: generate one, put its SHA-256 (`dpdp-rights hash-api-key <key>`) in
`api.auth.api_keys` in your config, and keep the key in Secret Manager. Note that the GCP template
sets `api.auth.mode: oidc`; change it to `both` if you add API keys.

People sign in through Identity Platform. The config expects a `roles` custom claim with values from
`principal`, `dpo`, `approver`. Set it with the Firebase Admin SDK:

```python
from firebase_admin import auth, initialize_app
initialize_app()
auth.set_custom_user_claims(auth.get_user_by_email("dpo@yourcompany.in").uid, {"roles": ["dpo"]})
```

To use another OIDC provider (Google Workspace, Okta, Entra ID), change `api.auth.oidc` (issuer,
audience, JWKS URL, roles claim).

## Step 8: Grant access to your stores

The Terraform roles cover Firestore, Cloud Logging (read), BigQuery, Vertex AI, DLP, GCS and Cloud
Trace at project level. Narrow them to specific resources where your organisation requires it, and
add roles for anything else your connectors touch. Agent runtimes that embed the SDK need the vault
key (`roles/cloudkms.cryptoKeyEncrypterDecrypter`), Firestore, DLP, Vertex AI and access to the
database and config secrets.

## Step 9: Smoke test

From inside the VPC (or with a Google identity token if you allowed it):

```bash
API=$(gcloud run services describe dpdp-rights-api --region=$REGION --format='value(status.url)')
TOKEN=$(gcloud auth print-identity-token --audiences=$API)
curl -s -H "X-Serverless-Authorization: Bearer $TOKEN" "$API/healthz"
```

Then follow the same request flow as in [deploy-aws.md](deploy-aws.md#step-8-smoke-test), and
validate your connectors in a non-production project ([testing.md](testing.md#testing-on-google-cloud)).

When Cloud Run IAM sits in front of the API, send the Google identity token in
`X-Serverless-Authorization`, which Cloud Run accepts in place of `Authorization`. That leaves
`Authorization: Bearer <Identity Platform token>` (or `x-api-key`) for the framework's own
authentication.

## Updating

- **Config**: `gcloud secrets versions add dpdp-config --data-file=...`, then redeploy the services (a
  new revision picks up `latest`).
- **New version**: build and push a new tag, `gcloud run deploy ... --image=<new tag>` for API and
  worker, `gcloud run jobs update` for the purge job.

The day-to-day runbook is in [operations.md](operations.md).
