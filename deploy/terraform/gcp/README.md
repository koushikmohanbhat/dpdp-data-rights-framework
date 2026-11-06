# Google Cloud stack

Creates the security-critical resources in your project: Cloud KMS keys (vault, sealed with
break-glass decrypt, certificate signing), Firestore vault database, certificate bucket with a
locked retention policy, the framework's service account and roles, and the escrow-purge schedule.
Cloud SQL, Cloud Run and Identity Platform are set up with `gcloud`.

**Full guide: [docs/deploy-gcp.md](../../../docs/deploy-gcp.md).**

```bash
terraform init
terraform apply -var-file ~/my-dpdp-deployment/gcp.tfvars    # project, region, break_glass_group
```

The certificate bucket's retention lock is irreversible. Use `certificate_retention_days = 1` in test
projects.
