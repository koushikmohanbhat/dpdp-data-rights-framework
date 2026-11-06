# Google Cloud infrastructure: Cloud KMS key for the vault, Firestore database,
# service account with least-privilege roles, daily Cloud Scheduler job for escrow purges.

terraform {
  required_providers {
    google = { source = "hashicorp/google", version = ">= 5.30" }
  }
}

variable "project" {}
variable "region" { default = "asia-south1" }
variable "purge_job_uri" {
  description = "Cloud Run job :run endpoint that executes `dpdp-rights purge-escrows`"
  default     = ""
}

provider "google" {
  project = var.project
  region  = var.region
}

resource "google_kms_key_ring" "dpdp" {
  name     = "dpdp"
  location = var.region
}

resource "google_kms_crypto_key" "vault_kek" {
  name            = "vault-kek"
  key_ring        = google_kms_key_ring.dpdp.id
  rotation_period = "7776000s" # 90 days
}

resource "google_firestore_database" "vault" {
  name        = "dpdp-vault"
  location_id = var.region
  type        = "FIRESTORE_NATIVE"
}

resource "google_service_account" "orchestrator" {
  account_id   = "dpdp-erasure"
  display_name = "DPDP erasure orchestrator"
}

resource "google_kms_crypto_key_iam_member" "vault" {
  crypto_key_id = google_kms_crypto_key.vault_kek.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:${google_service_account.orchestrator.email}"
}

resource "google_project_iam_member" "roles" {
  for_each = toset([
    "roles/datastore.user",      # vault on Firestore
    "roles/logging.viewer",      # discovery + verification
    "roles/bigquery.dataEditor", # DML erase in warehouse
    "roles/bigquery.jobUser",
    "roles/aiplatform.user",     # Vertex models, Vector Search, Memory Bank
    "roles/dlp.user",            # PII detection
    "roles/storage.objectAdmin", # eval / fine-tune datasets on GCS
  ])
  project = var.project
  role    = each.value
  member  = "serviceAccount:${google_service_account.orchestrator.email}"
}

resource "google_cloud_scheduler_job" "purge_escrows" {
  count     = var.purge_job_uri == "" ? 0 : 1
  name      = "dpdp-purge-escrows"
  schedule  = "0 2 * * *"
  time_zone = "Asia/Kolkata"
  http_target {
    uri         = var.purge_job_uri
    http_method = "POST"
    oauth_token { service_account_email = google_service_account.orchestrator.email }
  }
}

output "kms_key" { value = google_kms_crypto_key.vault_kek.id }
output "service_account" { value = google_service_account.orchestrator.email }
