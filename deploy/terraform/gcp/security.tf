# Production hardening resources (v0.2): sealed KEK with decrypt reserved for a break-glass group,
# asymmetric certificate signing key, GCS bucket with a locked retention policy, extra roles.

variable "break_glass_group" {
  description = "Google group (e.g. group:dpdp-break-glass@example.com) allowed to decrypt sealed data"
  type        = string
}
variable "certificate_retention_days" { default = 3650 }

resource "google_kms_crypto_key" "sealed_kek" {
  name            = "sealed-kek"
  key_ring        = google_kms_key_ring.dpdp.id
  rotation_period = "7776000s"
}

resource "google_kms_crypto_key_iam_member" "sealed_app_encrypt" {
  crypto_key_id = google_kms_crypto_key.sealed_kek.id
  role          = "roles/cloudkms.cryptoKeyEncrypter" # encrypt only
  member        = "serviceAccount:${google_service_account.orchestrator.email}"
}

resource "google_kms_crypto_key_iam_member" "sealed_break_glass_decrypt" {
  crypto_key_id = google_kms_crypto_key.sealed_kek.id
  role          = "roles/cloudkms.cryptoKeyDecrypter"
  member        = var.break_glass_group
}

resource "google_kms_crypto_key" "cert_signing" {
  name     = "cert-signing"
  key_ring = google_kms_key_ring.dpdp.id
  purpose  = "ASYMMETRIC_SIGN"
  version_template {
    algorithm = "EC_SIGN_P256_SHA256"
  }
}

resource "google_kms_crypto_key_iam_member" "cert_signer" {
  crypto_key_id = google_kms_crypto_key.cert_signing.id
  role          = "roles/cloudkms.signerVerifier"
  member        = "serviceAccount:${google_service_account.orchestrator.email}"
}

resource "google_storage_bucket" "certificates" {
  name                        = "${var.project}-dpdp-certificates"
  location                    = var.region
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  retention_policy {
    retention_period = var.certificate_retention_days * 86400
    is_locked        = true # irreversible: objects cannot be deleted before the period ends
  }
}

resource "google_storage_bucket_iam_member" "certificates_writer" {
  bucket = google_storage_bucket.certificates.name
  role   = "roles/storage.objectCreator"
  member = "serviceAccount:${google_service_account.orchestrator.email}"
}

resource "google_project_iam_member" "hardening_roles" {
  for_each = toset(["roles/cloudtrace.user"])
  project  = var.project
  role     = each.value
  member   = "serviceAccount:${google_service_account.orchestrator.email}"
}

output "sealed_kek" { value = google_kms_crypto_key.sealed_kek.id }
output "cert_signing_key" { value = google_kms_crypto_key.cert_signing.id }
output "certificate_bucket" { value = google_storage_bucket.certificates.name }
